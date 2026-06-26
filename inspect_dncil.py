import dncil

print("dncil modules:")
print(dir(dncil))
# Let's inspect submodules
import dncil.cil
print("dncil.cil modules:")
print(dir(dncil.cil))

# Let's search inside the packages
import pkgutil
for loader, module_name, is_pkg in pkgutil.walk_packages(dncil.__path__, dncil.__name__ + '.'):
    print(module_name)
