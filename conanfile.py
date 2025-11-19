from conan import ConanFile
from conan.tools.cmake import CMake
from conan.tools.env import VirtualRunEnv



class CompressorRecipe(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeToolchain", "CMakeDeps", "VirtualRunEnv"

    def requirements(self):
        self.requires("cli11/[>=2.6.0 <3]")
        self.requires("libsodium/[>=1.0.20 <2]")
        self.requires("nlohmann_json/[>=3.12.0 <4]")
        self.requires("spdlog/[>=1.16.0 <2]")

    def build_requirements(self):
        pass

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

