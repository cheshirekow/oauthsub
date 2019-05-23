import os
import zipfile

import jinja2


class ZipfileLoader(jinja2.BaseLoader):
  """
  Jinja template loader capable of loading templates from a zipfile
  """

  def __init__(self, zipfile_path, directory):
    self.zip = zipfile.ZipFile(zipfile_path, mode='r')
    self.dir = directory

  def __del__(self):
    self.zip.close()

  def get_source(self, environment, template):
    # NOTE(josh): not os.path because zipfile uses forward slash
    tplpath = '{}/{}'.format(self.dir, template)
    with self.zip.open(tplpath, 'r') as infile:
      source = infile.read().decode('utf-8')

    return source, tplpath, lambda: True


def get_zipfile_path(modparent):
  """
  If our module is loaded from a zipfile (e.g. a wheel or egg) then return
  the pair (zipfile_path, module_relpath) where zipfile_path is the path to
  the zipfile and module_relpath is the relative path within that zipfile.
  """
  zipfile_parts = modparent.split(os.sep)
  module_parts = []

  while zipfile_parts:
    zipfile_path = os.sep.join(zipfile_parts)
    relative_path = "/".join(module_parts)
    if os.path.exists(zipfile_path) and zipfile.is_zipfile(zipfile_path):
      return zipfile_path, relative_path
    module_parts.insert(0, zipfile_parts.pop(-1))

  return None, None
