"""Rules for importing Nixpkgs packages."""

load("@bazel_skylib//lib:sets.bzl", "sets")
load("@bazel_skylib//lib:versions.bzl", "versions")
load("@bazel_tools//tools/cpp:cc_configure.bzl", "cc_autoconf_impl")
load(
    "@bazel_tools//tools/cpp:lib_cc_configure.bzl",
    "get_cpu_value",
    "get_starlark_list",
    "write_builtin_include_directory_paths",
)
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load(":private/location_expansion.bzl", "expand_location")

NIX_ENVVARS = [
    "NIX_CC",
    "NIX_CLFAGS_COMPILE",
    "NIX_CXXSTDLIB_COMPILE",
    "NIX_BINTOOLS",
]

def in_nix_environment(env):
    for key in NIX_ENVVARS:
        if key not in env:
            return False
    return True

def _get_include_dirs(repository_ctx, compiler):
    result = _execute_or_fail(repository_ctx, [
        compiler,
        "-E",
        "-x",
        "c++",
        "-",
        "-v",
    ], failure_message = "Failed to get builtin includes")

    gatheringInc = False
    gatheringSys = False

    out = []
    for line in result.stderr.splitlines():
        if line == '#include "..." search starts here:':
            gatheringInc = True
            gatheringSys = False
        elif line == "#include <...> search starts here:":
            gatheringInc = False
            gatheringSys = True
        elif line == "End of search list.":
            gatheringSys = False
            gatheringInc = False
        elif gatheringInc:
            out.append(line.strip())
        elif gatheringSys:
            out.append(line.strip())

    return out

def _is_linker_option_supported(repository_ctx, compiler, option):
    result = repository_ctx.execute([
        compiler,
        option,
        "-x",
        "c++",
        "-Werror",
        "-o",
        "/dev/null",
        Label("@io_tweag_rules_nixpkgs//nixpkgs/toolchains:test.cc"),
    ])
    return result.return_code == 0

def _is_compiler_option_supported(repository_ctx, compiler, option):
    result = repository_ctx.execute([
        compiler,
        option,
        "-c",
        "-x",
        "c++",
        "-Werror",
        "-o",
        "/dev/null",
        Label("@io_tweag_rules_nixpkgs//nixpkgs/toolchains:test.cc"),
    ])
    return result.return_code == 0

def _nixpkgs_git_repository_impl(repository_ctx):
    if in_nix_environment(repository_ctx.os.environ):
        print("Overriding")

    repository_ctx.file(
        "BUILD",
        content = 'filegroup(name = "srcs", srcs = glob(["**"]), visibility = ["//visibility:public"])',
    )

    # Make "@nixpkgs" (syntactic sugar for "@nixpkgs//:nixpkgs") a valid
    # label for default.nix.
    repository_ctx.symlink("default.nix", repository_ctx.name)

    repository_ctx.download_and_extract(
        url = "%s/archive/%s.tar.gz" % (repository_ctx.attr.remote, repository_ctx.attr.revision),
        stripPrefix = "nixpkgs-" + repository_ctx.attr.revision,
        sha256 = repository_ctx.attr.sha256,
    )

nixpkgs_git_repository = repository_rule(
    implementation = _nixpkgs_git_repository_impl,
    attrs = {
        "revision": attr.string(
            mandatory = True,
            doc = "Git commit hash or tag identifying the version of Nixpkgs to use.",
        ),
        "remote": attr.string(
            default = "https://github.com/NixOS/nixpkgs",
            doc = "The URI of the remote Git repository. This must be a HTTP URL. There is currently no support for authentication. Defaults to [upstream nixpkgs](https://github.com/NixOS/nixpkgs).",
        ),
        "sha256": attr.string(doc = "The SHA256 used to verify the integrity of the repository."),
    },
    doc = """\
Name a specific revision of Nixpkgs on GitHub or a local checkout.
""",
)

def _nixpkgs_local_repository_impl(repository_ctx):
    if in_nix_environment(repository_ctx.os.environ):
        print("Overriding")

    if not bool(repository_ctx.attr.nix_file) != \
       bool(repository_ctx.attr.nix_file_content):
        fail("Specify one of 'nix_file' or 'nix_file_content' (but not both).")
    if repository_ctx.attr.nix_file_content:
        repository_ctx.file(
            path = "default.nix",
            content = repository_ctx.attr.nix_file_content,
            executable = False,
        )
        target = repository_ctx.path("default.nix")
    else:
        target = _cp(repository_ctx, repository_ctx.attr.nix_file)

    repository_files = [target]
    for dep in repository_ctx.attr.nix_file_deps:
        dest = _cp(repository_ctx, dep)
        repository_files.append(dest)

    # Export all specified Nix files to make them dependencies of a
    # nixpkgs_package rule.
    export_files = "exports_files({})".format(repository_files)
    repository_ctx.file("BUILD", content = export_files)

    # Create a file listing all Nix files of this repository. This
    # file is used by the nixpgks_package rule to register all Nix
    # files.
    repository_ctx.file("nix-file-deps", content = "\n".join(repository_files))

    # Make "@nixpkgs" (syntactic sugar for "@nixpkgs//:nixpkgs") a valid
    # label for the target Nix file.
    repository_ctx.symlink(target, repository_ctx.name)

nixpkgs_local_repository = repository_rule(
    implementation = _nixpkgs_local_repository_impl,
    attrs = {
        "nix_file": attr.label(
            allow_single_file = [".nix"],
            doc = "A file containing an expression for a Nix derivation.",
        ),
        "nix_file_deps": attr.label_list(
            doc = "Dependencies of `nix_file` if any.",
        ),
        "nix_file_content": attr.string(
            doc = "An expression for a Nix derivation.",
        ),
    },
    doc = """\
Create an external repository representing the content of Nixpkgs, based on a Nix expression stored locally or provided inline. One of `nix_file` or `nix_file_content` must be provided.
""",
)

def filter_empty(lst):
    out = []
    for f in lst:
        f = f.strip()
        if f != "":
            out.append(f)
    return out

def read_build_inputs(stringList):
    if stringList == None:
        fail("Must provide a list of 'attr1=path1:attr2=path2:...")

    output = {}
    attrMapStrings = stringList.split(":")
    for s in attrMapStrings:
        key, value = s.split("=")
        output[key] = value
    return output

def _is_supported_platform(repository_ctx):
    return repository_ctx.which("nix-build") != None

def _build_nixpkg(repository_ctx):
    repository = repository_ctx.attr.repository
    repositories = repository_ctx.attr.repositories

    if repository and repositories or not repository and not repositories:
        fail("Specify one of 'repository' or 'repositories' (but not both).")
    elif repository:
        repositories = {repository_ctx.attr.repository: "nixpkgs"}

    # Is nix supported on this platform?
    not_supported = not _is_supported_platform(repository_ctx)

    # Should we fail if Nix is not supported?
    if not_supported and repository_ctx.attr.fail_not_supported:
        fail("Platform is not supported: nix-build not found in PATH. See attribute fail_not_supported if you don't want to use Nix.")
    elif not_supported:
        return []

    strFailureImplicitNixpkgs = (
        "One of 'repositories', 'nix_file' or 'nix_file_content' must be provided. " +
        "The NIX_PATH environment variable is not inherited."
    )

    expr_args = []
    if not repositories:
        fail(strFailureImplicitNixpkgs)
    else:
        expr_args = ["-E", "import <nixpkgs>"]

    for _, attribute_path in repository_ctx.attr.attribute_paths.items():
        expr_args.extend([
            "-A",
            attribute_path,
        ])
    expr_args.extend([
        # Creating an out link prevents nix from garbage collecting the store path.
        # nixpkgs uses `nix-support/` for such house-keeping files, so we mirror them
        # and use `bazel-support/`, under the assumption that no nix package has
        # a file named `bazel-support` in its root.
        # A `bazel clean` deletes the symlink and thus nix is free to garbage collect
        # the store path.
        "--out-link",
        "bazel-support/{}".format(repository_ctx.name),
    ])

    expr_args.extend([
        expand_location(
            repository_ctx = repository_ctx,
            string = opt,
            labels = None,
            attr = "nixopts",
        )
        for opt in repository_ctx.attr.nixopts
    ])

    for repo in repositories.keys():
        path = str(repository_ctx.path(repo).dirname) + "/nix-file-deps"
        if repository_ctx.path(path).exists:
            content = repository_ctx.read(path)
            for f in content.splitlines():
                # Hack: this is to register all Nix files as dependencies
                # of this rule (see issue #113)
                repository_ctx.path(repo.relative(":{}".format(f)))

    # If repositories is not set, leave empty so nix will fail
    # unless a pinned nixpkgs is set in the `nix_file` attribute.
    nix_path = [
        "{}={}".format(prefix, repository_ctx.path(repo))
        for (repo, prefix) in repositories.items()
    ]
    if not repositories:
        fail(strFailureImplicitNixpkgs)

    for dir in nix_path:
        expr_args.extend(["-I", dir])

    nix_build_path = _executable_path(
        repository_ctx,
        "nix-build",
        extra_msg = "See: https://nixos.org/nix/",
    )
    nix_build = [nix_build_path] + expr_args

    # Large enough integer that Bazel can still parse. We don't have
    # access to MAX_INT and 0 is not a valid timeout so this is as good
    # as we can do. The value shouldn't be too large to avoid errors on
    # macOS, see https://github.com/tweag/rules_nixpkgs/issues/92.
    timeout = 8640000
    repository_ctx.report_progress("Building Nix derivation")
    exec_result = _execute_or_fail(
        repository_ctx,
        nix_build,
        failure_message = "Cannot build Nix attribute '{}'.".format(
            repository_ctx.attr.attribute_paths,
        ),
        quiet = repository_ctx.attr.quiet,
        timeout = timeout,
        environment = {"NIXPKGS_ALLOW_UNFREE": "1", "NIX_PROFILES": "/nix/var/nix/profiles/default"},
    )
    return exec_result.stdout.splitlines()

def match_count(leftList, rightList):
    # match in order
    if len(leftList) == 0 or len(rightList) == 0:
        return 0

    a = int(leftList[0] == rightList[0]) + match_count(leftList[1:], rightList[1:])
    b = match_count(leftList[1:], rightList)
    c = match_count(leftList, rightList[1:])
    return max(max(a, b), c)

def _match_inputs_to_attributes(buildInputs, attr_map):
    name_with_paths = []
    for path in buildInputs:
        # should be one of:
        # /nix/store/z4zqsz220zsrfdrllmxs2zapnmzp12g6-<name>-<version>-<suffix>
        # /nix/store/z4zqsz220zsrfdrllmxs2zapnmzp12g6-<name>-<version>
        if not path.startswith("/nix/store/") or len(path) < 44:
            fail("Unknown path type: %s" % path)
        name_with_paths.append((path[44:], path))

    outputs = []
    for attr_name, attr_path in attr_map.items():
        found = False
        for name, path in name_with_paths:
            if attr_name == name:
                found = True
                outputs.append(path)
                break
        if not found:
            fail("No build input found to match attribute: {}".format(attr_name))

    if len(outputs) != len(attr_map):
        fail("Unknown failure while matching attributes")
    return outputs

def _nixpkgs_package_impl(repository_ctx):
    bazelBuildInputs = read_build_inputs(repository_ctx.os.environ.get("bazelBuildInputs"))

    # If true, a BUILD file will be created from a template if it does not
    # exits.
    # However this will happen AFTER the nix-build command.
    create_build_file_if_needed = False
    if repository_ctx.attr.build_file and repository_ctx.attr.build_file_content:
        fail("Specify one of 'build_file' or 'build_file_content', but not both.")
    elif repository_ctx.attr.build_file:
        repository_ctx.symlink(repository_ctx.attr.build_file, "BUILD")
    elif repository_ctx.attr.build_file_content:
        repository_ctx.file("BUILD", content = repository_ctx.attr.build_file_content)
    else:
        # No user supplied build file, we may create the default one.
        create_build_file_if_needed = True

    if bazelBuildInputs == None:
        # we're outside nix so we should be able to build the packages directly
        output_paths = _build_nixpkg(repository_ctx)
    else:
        # we're inside nix, remap
        output_paths = []
        for attr in repository_ctx.attr.attribute_paths:
            if attr not in bazelBuildInputs:
                fail("Attr %s not passed to bazelBuildInputs, value: '%s', should be of the form attr1=value1:attr2=value2...")
            output_paths.append(bazelBuildInputs[attr])

    # ensure that the output is a directory
    test_path = repository_ctx.which("test")
    for output_path in output_paths:
        _execute_or_fail(
            repository_ctx,
            [test_path, "-d", output_path],
            failure_message = "nixpkgs_package '@{}' outputs a single file which is not supported by rules_nixpkgs. Please only use directories.".format(
                repository_ctx.name,
            ),
        )

    # Build a forest of symlinks (like new_local_package() does) to the
    # Nix store.
    for attribute_path, output_path in zip(repository_ctx.attr.attribute_paths, output_paths):
        repository_ctx.symlink(output_path, attribute_path)

    # Create a default BUILD file only if it does not exists and is not
    # provided by `build_file` or `build_file_content`.
    if create_build_file_if_needed:
        p = repository_ctx.path("BUILD")
        if not p.exists:
            repository_ctx.template("BUILD", Label("@io_tweag_rules_nixpkgs//nixpkgs:BUILD.pkg"))

_nixpkgs_package = repository_rule(
    implementation = _nixpkgs_package_impl,
    environ = ["buildInputs", "nativeBuildInputs", "propagatedBuildInputs"],
    attrs = {
        "attribute_paths": attr.string_dict(),  # maps from name to attribute
        "repositories": attr.label_keyed_string_dict(),
        "repository": attr.label(),
        "build_file": attr.label(),
        "build_file_content": attr.string(),
        "nixopts": attr.string_list(),
        "quiet": attr.bool(),
        "fail_not_supported": attr.bool(default = True, doc = """
            If set to True (default) this rule will fail on platforms which do not support Nix (e.g. Windows). If set to False calling this rule will succeed but no output will be generated.
                                        """),
    },
)

def nixpkgs_package(
        name,
        attribute_paths,
        repository = None,
        repositories = {},
        build_file = None,
        build_file_content = "",
        nixopts = [],
        quiet = False,
        fail_not_supported = True,
        **kwargs):
    """Make the content of a Nixpkgs package available in the Bazel workspace.

    If `repositories` is not specified, you must provide a nixpkgs clone in `nix_file` or `nix_file_content`.

    Args:
      name: A unique name for this repository.
      attribute_paths: List of attributes to build and symlink in the build directory
      nix_file_content: An expression for a Nix derivation.
      repository: A repository label identifying which Nixpkgs to use. Equivalent to `repositories = { "nixpkgs": ...}`
      repositories: A dictionary mapping `NIX_PATH` entries to repository labels.

        Setting it to
        ```
        repositories = { "myrepo" : "//:myrepo" }
        ```
        for example would replace all instances of `<myrepo>` in the called nix code by the path to the target `"//:myrepo"`. See the [relevant section in the nix manual](https://nixos.org/nix/manual/#env-NIX_PATH) for more information.

        Specify one of `repository` or `repositories`.
      build_file: The file to use as the BUILD file for this repository.

        Its contents are copied copied into the file `BUILD` in root of the nix output folder. The Label does not need to be named `BUILD`, but can be.

        For common use cases we provide filegroups that expose certain files as targets:

        <dl>
          <dt><code>:bin</code></dt>
          <dd>Everything in the <code>bin/</code> directory.</dd>
          <dt><code>:lib</code></dt>
          <dd>All <code>.so</code> and <code>.a</code> files that can be found in subdirectories of <code>lib/</code>.</dd>
          <dt><code>:include</code></dt>
          <dd>All <code>.h</code> files that can be found in subdirectories of <code>bin/</code>.</dd>
        </dl>

        If you need different files from the nix package, you can reference them like this:
        ```
        package(default_visibility = [ "//visibility:public" ])
        filegroup(
            name = "our-docs",
            srcs = glob(["share/doc/ourpackage/**/*"]),
        )
        ```
        See the bazel documentation of [`filegroup`](https://docs.bazel.build/versions/master/be/general.html#filegroup) and [`glob`](https://docs.bazel.build/versions/master/be/functions.html#glob).
      build_file_content: Like `build_file`, but a string of the contents instead of a file name.
      nixopts: Extra flags to pass when calling Nix.
      quiet: Whether to hide the output of the Nix command.
      fail_not_supported: If set to `True` (default) this rule will fail on platforms which do not support Nix (e.g. Windows). If set to `False` calling this rule will succeed but no output will be generated.
    """
    kwargs.update(
        name = name,
        attribute_paths = attribute_paths,
        repository = repository,
        repositories = repositories,
        build_file = build_file,
        build_file_content = build_file_content,
        nixopts = nixopts,
        quiet = quiet,
        fail_not_supported = fail_not_supported,
    )

    # Because of https://github.com/bazelbuild/bazel/issues/7989 we can't
    # directly pass a dict from strings to labels to the rule (which we'd like
    # for the `repositories` arguments), but we can pass a dict from labels to
    # strings. So we swap the keys and the values (assuming they all are
    # distinct).
    if "repositories" in kwargs:
        inversed_repositories = {value: key for (key, value) in kwargs["repositories"].items()}
        kwargs["repositories"] = inversed_repositories

    _nixpkgs_package(**kwargs)

def _nixpkgs_cc_toolchain_config_impl(repository_ctx):
    cpu_value = get_cpu_value(repository_ctx)
    darwin = cpu_value == "darwin"

    # Generate the cc_toolchain workspace following the example from
    # `@bazel_tools//tools/cpp:unix_cc_configure.bzl`.
    # Uses the corresponding templates from `@bazel_tools` as well, see the
    # private attributes of the `_nixpkgs_cc_toolchain_config` rule.
    repository_ctx.symlink(
        repository_ctx.path(repository_ctx.attr._unix_cc_toolchain_config),
        "cc_toolchain_config.bzl",
    )
    repository_ctx.symlink(
        repository_ctx.path(repository_ctx.attr._armeabi_cc_toolchain_config),
        "armeabi_cc_toolchain_config.bzl",
    )

    cxx_builtin_include_directories = _get_include_dirs(repository_ctx, repository_ctx.attr.gcc)

    compile_flags = []
    for flag in [
        # Security hardening requires optimization.
        # We need to undef it as some distributions now have it enabled by default.
        "-U_FORTIFY_SOURCE",
        "-fstack-protector",
        # All warnings are enabled. Maybe enable -Werror as well?
        "-Wall",
        # Enable a few more warnings that aren't part of -Wall.
        "-Wthread-safety",
        "-Wself-assign",
        # Disable problematic warnings.
        "-Wunused-but-set-parameter",
        # has false positives
        "-Wno-free-nonheap-object",
        # Enable coloring even if there's no attached terminal. Bazel removes the
        # escape sequences if --nocolor is specified.
        "-fcolor-diagnostics",
        # Keep stack frames for debugging, even in opt mode.
        "-fno-omit-frame-pointer",
    ]:
        if _is_compiler_option_supported(repository_ctx, repository_ctx.attr.gcc, flag):
            compile_flags.append(flag)

    cxx_flags = [
        "-x c++",
        "-std=c++0x",
    ]

    link_flags = []
    for flag in [
        "-Wl,-no-as-needed",
        "-no-as-needed",
        "-Wl,-z,relro,-z,now",
        "-z",

        # Have gcc return the exit code from ld.
        "-pass-exit-codes",
    ]:
        if _is_linker_option_supported(repository_ctx, repository_ctx.attr.gcc, flag):
            link_flags.append(flag)

    if darwin:
        link_flags.extend([
            "-undefined dynamic_lookup",
            "-headerpad_max_install_names",
        ])
    else:
        link_flags.extend(["-B${cc}/bin", "-L${cc}/lib"])

    link_libs = [
        "-lstdc++",
        "-lm",
    ]

    opt_compile_flags = [
        # No debug symbols.
        # Maybe we should enable https://gcc.gnu.org/wiki/DebugFission for opt or
        # even generally? However, that can't happen here, as it requires special
        # handling in Bazel.
        "-g0",

        # Conservative choice for -O
        # -O3 can increase binary size and even slow down the resulting binaries.
        # Profile first and / or use FDO if you need better performance than this.
        "-O2",

        # Security hardening on by default.
        # Conservative choice; -D_FORTIFY_SOURCE=2 may be unsafe in some cases.
        "-D_FORTIFY_SOURCE=1",

        # Disable assertions
        "-DNDEBUG",

        # Removal of unused code and data at link time (can this increase binary
        # size in some cases?).
        "-ffunction-sections",
        "-fdata-sections",
    ]

    opt_link_flags = []
    if not darwin:
        opt_link_flags.extend(["-Wl,--gc-sections", "-gc-sections"])

    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-no-canonical-prefixes",
        "-Wno-builtin-macro-redefined",
        '-D__DATE__=\\\"redacted\\\"',
        '-D__TIMESTAMP__=\\\"redacted\\\"',
        '-D__TIME__=\\\"redacted\\\"',
    ]

    # Make C++ compilation deterministic. Use linkstamping instead of these
    # compiler symbols.
    dbg_compile_flags = ["-g"]

    if darwin:
        coverage_compile_flags = ["-fprofile-instr-generate", "-fcoverage-mapping"]
    else:
        coverage_compile_flags = ["--coverage"]

    if darwin:
        coverage_link_flags = ["-fprofile-instr-generate"]
    else:
        coverage_link_flags = ["--coverage"]

    supports_start_end_lib = False
    if repository_ctx.attr.ld.name.endswith("ld.gold"):
        link_flags.append("-fuse-ld=gold")
        supports_start_end_lib = True

    # TODO(micah) support ld.gold
    tool_paths = {
        "ar": repository_ctx.attr.ar,
        "cpp": repository_ctx.attr.cpp,
        "dwp": repository_ctx.attr.dwp,
        "gcc": repository_ctx.attr.gcc,
        "gcov": repository_ctx.attr.gcov,
        "ld": repository_ctx.attr.ld,
        "nm": repository_ctx.attr.nm,
        "objcopy": repository_ctx.attr.objcopy,
        "objdump": repository_ctx.attr.objdump,
        "strip": repository_ctx.attr.strip,
    }
    compile_flags = compile_flags
    cxx_flags = []
    link_libs = []
    opt_compile_flags = []
    opt_link_flags = []
    unfiltered_compile_flags = []
    dbg_compile_flags = []
    dbg_compile_flags = []
    coverage_compile_flags = ["--coverage"]
    coverage_link_flags = ["--coverage"]
    supports_start_end_lib = supports_start_end_lib
    is_clang = repository_ctx.attr.is_clang

    # A module map is required for clang starting from Bazel version 3.3.0.
    # https://github.com/bazelbuild/bazel/commit/8b9f74649512ee17ac52815468bf3d7e5e71c9fa
    needs_module_map = repository_ctx.attr.is_clang and versions.is_at_least("3.3.0", versions.get())
    if needs_module_map:
        generate_system_module_map = [
            repository_ctx.path(repository_ctx.attr._generate_system_module_map),
        ]
        repository_ctx.file(
            "module.modulemap",
            _execute_or_fail(
                repository_ctx,
                generate_system_module_map + cxx_builtin_include_directories,
                "Failed to generate system module map.",
            ).stdout.strip(),
            executable = False,
        )
    cc_wrapper_src = (
        repository_ctx.attr._osx_cc_wrapper if darwin else repository_ctx.attr._linux_cc_wrapper
    )
    repository_ctx.template(
        "cc_wrapper.sh",
        repository_ctx.path(cc_wrapper_src),
        {
            "%{cc}": tool_paths["gcc"].name,
            "%{env}": "",
        },
    )
    if darwin:
        tool_paths["gcc"] = "cc_wrapper.sh"
        tool_paths["ar"] = "/usr/bin/libtool"
    write_builtin_include_directory_paths(
        repository_ctx,
        tool_paths["gcc"],
        cxx_builtin_include_directories,
    )

    repository_ctx.template(
        "BUILD.bazel",
        repository_ctx.path(repository_ctx.attr._build),
        {
            "%{cc_toolchain_identifier}": "local",
            "%{name}": cpu_value,
            "%{modulemap}": ("\":module.modulemap\"" if needs_module_map else "None"),
            "%{supports_param_files}": "0" if darwin else "1",
            "%{cc_compiler_deps}": get_starlark_list(
                [":builtin_include_directory_paths"] + (
                    [":cc_wrapper"] if darwin else []
                ),
            ),
            "%{compiler}": "compiler",
            "%{abi_version}": "local",
            "%{abi_libc_version}": "local",
            "%{host_system_name}": "local",
            "%{target_libc}": "macosx" if darwin else "local",
            "%{target_cpu}": cpu_value,
            "%{target_system_name}": "local",
            "%{tool_paths}": ",\n        ".join(
                ['"%s": "%s"' % (k, repository_ctx.path(v)) for (k, v) in tool_paths.items()],
            ),
            "%{cxx_builtin_include_directories}": get_starlark_list(cxx_builtin_include_directories),
            "%{compile_flags}": get_starlark_list(compile_flags),
            "%{cxx_flags}": get_starlark_list(cxx_flags),
            "%{link_flags}": get_starlark_list(link_flags),
            "%{link_libs}": get_starlark_list(link_libs),
            "%{opt_compile_flags}": get_starlark_list(opt_compile_flags),
            "%{opt_link_flags}": get_starlark_list(opt_link_flags),
            "%{unfiltered_compile_flags}": get_starlark_list(unfiltered_compile_flags),
            "%{dbg_compile_flags}": get_starlark_list(dbg_compile_flags),
            "%{coverage_compile_flags}": get_starlark_list(coverage_compile_flags),
            "%{coverage_link_flags}": get_starlark_list(coverage_link_flags),
            "%{supports_start_end_lib}": repr(supports_start_end_lib),
        },
    )

_nixpkgs_cc_toolchain_config = repository_rule(
    _nixpkgs_cc_toolchain_config_impl,
    attrs = {
        "fail_not_supported": attr.bool(),
        "ar": attr.label(mandatory = True),
        "cpp": attr.label(mandatory = True),
        "dwp": attr.label(),
        "gcc": attr.label(mandatory = True),
        "gcov": attr.label(mandatory = True),
        "ld": attr.label(mandatory = True),
        "nm": attr.label(mandatory = True),
        "objcopy": attr.label(mandatory = True),
        "objdump": attr.label(mandatory = True),
        "strip": attr.label(),
        "is_clang": attr.bool(default = False),
        "_unix_cc_toolchain_config": attr.label(
            default = Label("@bazel_tools//tools/cpp:unix_cc_toolchain_config.bzl"),
        ),
        "_armeabi_cc_toolchain_config": attr.label(
            default = Label("@bazel_tools//tools/cpp:armeabi_cc_toolchain_config.bzl"),
        ),
        "_generate_system_module_map": attr.label(
            default = Label("@bazel_tools//tools/cpp:generate_system_module_map.sh"),
        ),
        "_osx_cc_wrapper": attr.label(
            default = Label("@bazel_tools//tools/cpp:osx_cc_wrapper.sh.tpl"),
        ),
        "_linux_cc_wrapper": attr.label(
            default = Label("@bazel_tools//tools/cpp:linux_cc_wrapper.sh.tpl"),
        ),
        "_build": attr.label(
            default = Label("@bazel_tools//tools/cpp:BUILD.tpl"),
        ),
    },
)

def _nixpkgs_cc_toolchain_impl(repository_ctx):
    cpu = get_cpu_value(repository_ctx)
    repository_ctx.file(
        "BUILD.bazel",
        executable = False,
        content = """\
package(default_visibility = ["//visibility:public"])

toolchain(
    name = "cc-toolchain-{cpu}",
    toolchain = "@{cc_toolchain_config}//:cc-compiler-{cpu}",
    toolchain_type = "@rules_cc//cc:toolchain_type",
    exec_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:{os}",
        "@io_tweag_rules_nixpkgs//nixpkgs/constraints:support_nix",
    ],
    target_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:{os}",
    ],
)

toolchain(
    name = "cc-toolchain-armeabi-v7a",
    toolchain = "@{cc_toolchain_config}//:cc-compiler-armeabi-v7a",
    toolchain_type = "@rules_cc//cc:toolchain_type",
    exec_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:{os}",
        "@io_tweag_rules_nixpkgs//nixpkgs/constraints:support_nix",
    ],
    target_compatible_with = [
        "@platforms//cpu:arm",
        "@platforms//os:android",
    ],
)
""".format(
            cc_toolchain_config = repository_ctx.attr.cc_toolchain_config,
            cpu = cpu,
            os = "osx" if cpu == "darwin" else "linux",
        ),
    )

_nixpkgs_cc_toolchain = repository_rule(
    _nixpkgs_cc_toolchain_impl,
    attrs = {
        "cc_toolchain_config": attr.string(),
    },
)

def nixpkgs_cc_configure(
        name,
        repositories = {},
        repository = None,
        nixopts = [],
        quiet = False,
        fail_not_supported = True):
    """Use a CC toolchain from Nixpkgs. No-op if not a nix-based platform.

    By default, Bazel auto-configures a CC toolchain from commands (e.g.
    `gcc`) available in the environment. To make builds more hermetic, use
    this rule to specify explicitly which commands the toolchain should use.

    Specifically, it builds a Nix derivation that provides the CC toolchain
    tools in the `bin/` path and constructs a CC toolchain that uses those
    tools. Tools that aren't found are replaced by `${coreutils}/bin/false`.
    You can inspect the resulting `@<name>_info//:CC_TOOLCHAIN_INFO` to see
    which tools were discovered.

    This rule depends on [`rules_cc`](https://github.com/bazelbuild/rules_cc).

    **Note:**
    You need to configure `--crosstool_top=@<name>//:toolchain` to activate
    this toolchain.

    Args:
      repositories: dict of Label to string, Provides `<nixpkgs>` and other repositories. Specify one of `repositories` or `repository`.
      repository: Label, Provides `<nixpkgs>`. Specify one of `repositories` or `repository`.
      nixopts: optional, list of string, Extra flags to pass when calling Nix. Subject to location expansion, any instance of `$(location LABEL)` will be replaced by the path to the file ferenced by `LABEL` relative to the workspace root.
      quiet: bool, Whether to hide `nix-build` output.
      fail_not_supported: bool, Whether to fail if `nix-build` is not available.
    """

    nixopts = list(nixopts)
    attribute_paths = {
        "pkgs.clang",
        "pkgs.gcc.cc",
        "pkgs.gcc.cc.lib",
        "pkgs.binutils.bintools",
    }

    # Invoke `toolchains/cc.nix` which generates `CC_TOOLCHAIN_INFO`.
    nixpkgs_package(
        name = "{}_pkg".format(name),
        build_file = "@io_tweag_rules_nixpkgs//nixpkgs/toolchains:cc.BUILD",
        repositories = repositories,
        repository = repository,
        attribute_paths = attribute_paths,
        nixopts = nixopts,
        quiet = quiet,
        fail_not_supported = fail_not_supported,
    )

    # Generate the `cc_toolchain_config` workspace.
    _nixpkgs_cc_toolchain_config(
        name = "{}".format(name),
        ar = "@{}_pkg//:pkgs.binutils.bintools/bin/ar".format(name),
        cpp = "@{}_pkg//:pkgs.clang/bin/cpp".format(name),
        dwp = "@{}_pkg//:pkgs.binutils.bintools/bin/dwp".format(name),
        gcc = "@{}_pkg//:pkgs.clang/bin/c++".format(name),
        gcov = "@{}_pkg//:pkgs.gcc.cc/bin/gcov".format(name),
        ld = "@{}_pkg//:pkgs.binutils.bintools/bin/ld".format(name),
        nm = "@{}_pkg//:pkgs.binutils.bintools/bin/nm".format(name),
        objdump = "@{}_pkg//:pkgs.binutils.bintools/bin/objdump".format(name),
        objcopy = "@{}_pkg//:pkgs.binutils.bintools/bin/objcopy".format(name),
        strip = "@{}_pkg//:pkgs.binutils.bintools/bin/strip".format(name),
        is_clang = True,
        fail_not_supported = fail_not_supported,
    )

    # Generate the `cc_toolchain` workspace.
    _nixpkgs_cc_toolchain(
        name = "{}_toolchains".format(name),
        cc_toolchain_config = name,
    )

    maybe(
        native.bind,
        name = "cc_toolchain",
        actual = "@{}//:toolchain".format(name),
    )
    native.register_toolchains("@{}_toolchains//:all".format(name))

def _readlink(repository_ctx, path):
    return repository_ctx.path(path).realpath

def nixpkgs_cc_autoconf_impl(repository_ctx):
    cpu_value = get_cpu_value(repository_ctx)
    if not _is_supported_platform(repository_ctx):
        cc_autoconf_impl(repository_ctx)
        return

    # Calling repository_ctx.path() on anything but a regular file
    # fails. So the roundabout way to do the same thing is to find
    # a regular file we know is in the workspace (i.e. the WORKSPACE
    # file itself) and then use dirname to get the path of the workspace
    # root.
    workspace_file_path = repository_ctx.path(
        Label("@nixpkgs_cc_toolchain//:WORKSPACE"),
    )
    workspace_root = _execute_or_fail(
        repository_ctx,
        ["dirname", workspace_file_path],
    ).stdout.rstrip()

    # Make a list of all available tools in the Nix derivation. Override
    # the Bazel autoconfiguration with the tools we found.
    bin_contents = _find_children(repository_ctx, workspace_root + "/bin")
    overriden_tools = {
        tool: _readlink(repository_ctx, entry)
        for entry in bin_contents
        for tool in [entry.rpartition("/")[-1]]  # Compute basename
    }
    cc_autoconf_impl(repository_ctx, overriden_tools = overriden_tools)

nixpkgs_cc_autoconf = repository_rule(
    implementation = nixpkgs_cc_autoconf_impl,
    # Copied from
    # https://github.com/bazelbuild/bazel/blob/master/tools/cpp/cc_configure.bzl.
    # Keep in sync.
    environ = [
        "ABI_LIBC_VERSION",
        "ABI_VERSION",
        "BAZEL_COMPILER",
        "BAZEL_HOST_SYSTEM",
        "BAZEL_LINKOPTS",
        "BAZEL_PYTHON",
        "BAZEL_SH",
        "BAZEL_TARGET_CPU",
        "BAZEL_TARGET_LIBC",
        "BAZEL_TARGET_SYSTEM",
        "BAZEL_USE_CPP_ONLY_TOOLCHAIN",
        "BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN",
        "BAZEL_USE_LLVM_NATIVE_COVERAGE",
        "BAZEL_VC",
        "BAZEL_VS",
        "BAZEL_LLVM",
        "USE_CLANG_CL",
        "CC",
        "CC_CONFIGURE_DEBUG",
        "CC_TOOLCHAIN_NAME",
        "CPLUS_INCLUDE_PATH",
        "GCOV",
        "HOMEBREW_RUBY_PATH",
        "SYSTEMROOT",
        "VS90COMNTOOLS",
        "VS100COMNTOOLS",
        "VS110COMNTOOLS",
        "VS120COMNTOOLS",
        "VS140COMNTOOLS",
    ],
)

def nixpkgs_cc_configure_deprecated(
        repository = None,
        repositories = {},
        nix_file = None,
        nix_file_deps = None,
        nix_file_content = None,
        nixopts = []):
    """Use a CC toolchain from Nixpkgs. No-op if not a nix-based platform.

    Tells Bazel to use compilers and linkers from Nixpkgs for the CC toolchain.
    By default, Bazel auto-configures a CC toolchain from commands available in
    the environment (e.g. `gcc`). Overriding this autodetection makes builds
    more hermetic and is considered a best practice.

    #### Example

      ```bzl
      nixpkgs_cc_configure(repository = "@nixpkgs//:default.nix")
      ```

    Args:
      repository: A repository label identifying which Nixpkgs to use.
        Equivalent to `repositories = { "nixpkgs": ...}`.
      repositories: A dictionary mapping `NIX_PATH` entries to repository labels.

        Setting it to
        ```
        repositories = { "myrepo" : "//:myrepo" }
        ```
        for example would replace all instances of `<myrepo>` in the called nix code by the path to the target `"//:myrepo"`. See the [relevant section in the nix manual](https://nixos.org/nix/manual/#env-NIX_PATH) for more information.

        Specify one of `repository` or `repositories`.
      nix_file: An expression for a Nix environment derivation.
        The environment should expose all the commands that make up a CC
        toolchain (`cc`, `ld` etc). Exposes all commands in `stdenv.cc` and
        `binutils` by default.
      nix_file_deps: Dependencies of `nix_file` if any.
      nix_file_content: An expression for a Nix environment derivation.
      nixopts: Options to forward to the nix command.

    Deprecated:
      Use `nixpkgs_cc_configure` instead.

      While this improves upon Bazel's autoconfigure toolchain by picking tools
      from a Nix derivation rather than the environment, it is still not fully
      hermetic as it is affected by the environment. In particular, system
      include directories specified in the environment can leak in and affect
      the cache keys of targets depending on the cc toolchain leading to cache
      misses.
    """
    if not nix_file and not nix_file_content:
        nix_file_content = """
          with import <nixpkgs>; buildEnv {
            name = "bazel-cc-toolchain";
            paths = [  ];
          }
        """
    nixpkgs_package(
        name = "nixpkgs_cc_toolchain",
        repository = repository,
        repositories = repositories,
        attribute_paths = [
            "stdenv.cc",
            "binutils",
        ],
        build_file_content = """exports_files(glob(["bin/*"]))""",
        nixopts = nixopts,
    )

    # Following lines should match
    # https://github.com/bazelbuild/bazel/blob/master/tools/cpp/cc_configure.bzl#L93.
    nixpkgs_cc_autoconf(name = "local_config_cc")
    native.bind(name = "cc_toolchain", actual = "@local_config_cc//:toolchain")
    native.register_toolchains("@local_config_cc//:all")

def _nixpkgs_python_toolchain_impl(repository_ctx):
    cpu = get_cpu_value(repository_ctx)
    repository_ctx.file("BUILD.bazel", executable = False, content = """
load("@bazel_tools//tools/python:toolchain.bzl", "py_runtime_pair")
py_runtime_pair(
    name = "py_runtime_pair",
    py2_runtime = {python2_runtime},
    py3_runtime = {python3_runtime},
)
toolchain(
    name = "toolchain",
    toolchain = ":py_runtime_pair",
    toolchain_type = "@bazel_tools//tools/python:toolchain_type",
    exec_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:{os}",
        "@io_tweag_rules_nixpkgs//nixpkgs/constraints:support_nix",
    ],
    target_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:{os}",
    ],
)
""".format(
        python2_runtime = _label_string(repository_ctx.attr.python2_runtime),
        python3_runtime = _label_string(repository_ctx.attr.python3_runtime),
        os = {"darwin": "osx"}.get(cpu, "linux"),
    ))

_nixpkgs_python_toolchain = repository_rule(
    _nixpkgs_python_toolchain_impl,
    attrs = {
        # Using attr.string instead of attr.label, so that the repository rule
        # does not explicitly depend on the nixpkgs_package instances. This is
        # necessary, so that builds don't fail on platforms without nixpkgs.
        "python2_runtime": attr.string(),
        "python3_runtime": attr.string(),
    },
)

_python_nix_file_content = """
with import <nixpkgs>;
runCommand "bazel-nixpkgs-python-toolchain"
  {{ executable = false;
    # Pointless to do this on a remote machine.
    preferLocalBuild = true;
    allowSubstitutes = false;
  }}
  ''
    n=$out/BUILD.bazel
    mkdir -p "$(dirname "$n")"

    cat >>$n <<EOF
    py_runtime(
        name = "runtime",
        interpreter_path = "${{{attribute_path}}}/{bin_path}",
        python_version = "{version}",
        visibility = ["//visibility:public"],
    )
    EOF
  ''
"""

def nixpkgs_python_configure(
        name = "nixpkgs_python_toolchain",
        python2_attribute_path = None,
        python2_bin_path = "bin/python",
        python3_attribute_path = "python3",
        python3_bin_path = "bin/python",
        repository = None,
        repositories = {},
        nix_file_deps = None,
        nixopts = [],
        fail_not_supported = True,
        quiet = False):
    """Define and register a Python toolchain provided by nixpkgs.

    Creates `nixpkgs_package`s for Python 2 or 3 `py_runtime` instances and a
    corresponding `py_runtime_pair` and `toolchain`. The toolchain is
    automatically registered and uses the constraint:

    ```
    "@io_tweag_rules_nixpkgs//nixpkgs/constraints:support_nix"
    ```

    Args:
      name: The name-prefix for the created external repositories.
      python2_attribute_path: The nixpkgs attribute path for python2.
      python2_bin_path: The path to the interpreter within the package.
      python3_attribute_path: The nixpkgs attribute path for python3.
      python3_bin_path: The path to the interpreter within the package.
      repository: See [`nixpkgs_package`](#nixpkgs_package-repository).
      repositories: See [`nixpkgs_package`](#nixpkgs_package-repositories).
      nix_file_deps: See [`nixpkgs_package`](#nixpkgs_package-nix_file_deps).
      nixopts: See [`nixpkgs_package`](#nixpkgs_package-nixopts).
      fail_not_supported: See [`nixpkgs_package`](#nixpkgs_package-fail_not_supported).
      quiet: See [`nixpkgs_package`](#nixpkgs_package-quiet).
    """
    python2_specified = python2_attribute_path and python2_bin_path
    python3_specified = python3_attribute_path and python3_bin_path
    if not python2_specified and not python3_specified:
        fail("At least one of python2 or python3 has to be specified.")
    kwargs = dict(
        repository = repository,
        repositories = repositories,
        nix_file_deps = nix_file_deps,
        nixopts = nixopts,
        fail_not_supported = fail_not_supported,
        quiet = quiet,
    )
    python2_runtime = None
    if python2_attribute_path:
        python2_runtime = "@%s_python2//:runtime" % name
        nixpkgs_package(
            name = name + "_python2",
            nix_file_content = _python_nix_file_content.format(
                attribute_path = python2_attribute_path,
                bin_path = python2_bin_path,
                version = "PY2",
            ),
            **kwargs
        )
    python3_runtime = None
    if python3_attribute_path:
        python3_runtime = "@%s_python3//:runtime" % name
        nixpkgs_package(
            name = name + "_python3",
            nix_file_content = _python_nix_file_content.format(
                attribute_path = python3_attribute_path,
                bin_path = python3_bin_path,
                version = "PY3",
            ),
            **kwargs
        )
    _nixpkgs_python_toolchain(
        name = name,
        python2_runtime = python2_runtime,
        python3_runtime = python3_runtime,
    )
    native.register_toolchains("@%s//:toolchain" % name)

def nixpkgs_sh_posix_config(name, packages, **kwargs):
    nixpkgs_package(
        name = name,
        nix_file_content = """
with import <nixpkgs>;

let
  # `packages` might include lists, e.g. `stdenv.initialPath` is a list itself,
  # so we need to flatten `packages`.
  flatten = builtins.concatMap (x: if builtins.isList x then x else [x]);
  env = buildEnv {{
    name = "posix-toolchain";
    paths = flatten [ {} ];
  }};
  cmd_glob = "${{env}}/bin/*";
  os = if stdenv.isDarwin then "osx" else "linux";
in

runCommand "bazel-nixpkgs-posix-toolchain"
  {{ executable = false;
    # Pointless to do this on a remote machine.
    preferLocalBuild = true;
    allowSubstitutes = false;
  }}
  ''
    n=$out/nixpkgs_sh_posix.bzl
    mkdir -p "$(dirname "$n")"

    cat >>$n <<EOF
    load("@rules_sh//sh:posix.bzl", "posix", "sh_posix_toolchain")
    discovered = {{
    EOF
    for cmd in ${{cmd_glob}}; do
        if [[ -x $cmd ]]; then
            echo "    '$(basename $cmd)': '$cmd'," >>$n
        fi
    done
    cat >>$n <<EOF
    }}
    def create_posix_toolchain():
        sh_posix_toolchain(
            name = "nixpkgs_sh_posix",
            cmds = {{
                cmd: discovered[cmd]
                for cmd in posix.commands
                if cmd in discovered
            }}
        )
    EOF
  ''
""".format(" ".join(packages)),
        build_file_content = """
load("//:nixpkgs_sh_posix.bzl", "create_posix_toolchain")
create_posix_toolchain()
""",
        **kwargs
    )

def _nixpkgs_sh_posix_toolchain_impl(repository_ctx):
    cpu = get_cpu_value(repository_ctx)
    repository_ctx.file("BUILD", executable = False, content = """
toolchain(
    name = "nixpkgs_sh_posix_toolchain",
    toolchain = "@{workspace}//:nixpkgs_sh_posix",
    toolchain_type = "@rules_sh//sh/posix:toolchain_type",
    exec_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:{os}",
        "@io_tweag_rules_nixpkgs//nixpkgs/constraints:support_nix",
    ],
    target_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:{os}",
    ],
)
    """.format(
        workspace = repository_ctx.attr.workspace,
        os = {"darwin": "osx"}.get(cpu, "linux"),
    ))

_nixpkgs_sh_posix_toolchain = repository_rule(
    _nixpkgs_sh_posix_toolchain_impl,
    attrs = {
        "workspace": attr.string(),
    },
)

def nixpkgs_sh_posix_configure(
        name = "nixpkgs_sh_posix_config",
        packages = ["stdenv.initialPath"],
        **kwargs):
    """Create a POSIX toolchain from nixpkgs.

    Loads the given Nix packages, scans them for standard Unix tools, and
    generates a corresponding `sh_posix_toolchain`.

    Make sure to call `nixpkgs_sh_posix_configure` before `sh_posix_configure`,
    if you use both. Otherwise, the local toolchain will always be chosen in
    favor of the nixpkgs one.

    Args:
      name: Name prefix for the generated repositories.
      packages: List of Nix attribute paths to draw Unix tools from.
      nix_file_deps: See nixpkgs_package.
      repositories: See nixpkgs_package.
      repository: See nixpkgs_package.
      nixopts: See nixpkgs_package.
      fail_not_supported: See nixpkgs_package.
    """
    nixpkgs_sh_posix_config(
        name = name,
        packages = packages,
        **kwargs
    )

    # The indirection is required to avoid errors when `nix-build` is not in `PATH`.
    _nixpkgs_sh_posix_toolchain(
        name = name + "_toolchain",
        workspace = name,
    )
    native.register_toolchains(
        "@{}//:nixpkgs_sh_posix_toolchain".format(name + "_toolchain"),
    )

def _execute_or_fail(repository_ctx, arguments, failure_message = "", *args, **kwargs):
    """Call repository_ctx.execute() and fail if non-zero return code."""
    result = repository_ctx.execute(arguments, *args, **kwargs)
    if result.return_code:
        outputs = dict(
            failure_message = failure_message,
            arguments = arguments,
            return_code = result.return_code,
            stderr = result.stderr,
        )
        fail("""
{failure_message}
Command: {arguments}
Return code: {return_code}
Error output:
{stderr}
""".format(**outputs))
    return result

def _find_children(repository_ctx, target_dir):
    find_args = [
        _executable_path(repository_ctx, "find"),
        "-L",
        target_dir,
        "-maxdepth",
        "1",
        # otherwise the directory is printed as well
        "-mindepth",
        "1",
        # filenames can contain \n
        "-print0",
    ]
    exec_result = _execute_or_fail(repository_ctx, find_args)
    return exec_result.stdout.rstrip("\000").split("\000")

def _executable_path(repository_ctx, exe_name, extra_msg = ""):
    """Try to find the executable, fail with an error."""
    path = repository_ctx.which(exe_name)
    if path == None:
        fail("Could not find the `{}` executable in PATH.{}\n"
            .format(exe_name, " " + extra_msg if extra_msg else ""))
    return path

def _cp(repository_ctx, src, dest = None):
    """Copy the given file into the external repository root.

    Args:
      repository_ctx: The repository context of the current repository rule.
      src: The source file. Must be a Label if dest is None.
      dest: Optional, The target path within the current repository root.
        By default the relative path to the repository root is preserved.

    Returns:
      The dest value
    """
    if dest == None:
        if type(src) != "Label":
            fail("src must be a Label if dest is not specified explicitly.")
        dest = "/".join([
            component
            for component in [src.workspace_root, src.package, src.name]
            if component
        ])
    repository_ctx.template(dest, src, executable = False)
    return dest

def _label_string(label):
    """Convert the given (optional) Label to a string."""
    if not label:
        return "None"
    else:
        return '"%s"' % label
