-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 SerenIT ApS and Prompted EV
--
-- Publish's renderer (D-049): an image becomes its caption, so pandoc reads
-- no file of the box and fetches no address into an artifact. Ubuntu's
-- pandoc cannot render .docx or .pptx under --sandbox (its data files are
-- not built in), so this is the guard instead.
function Image(el)
  return pandoc.Str("[image: " .. pandoc.utils.stringify(el.caption) .. "]")
end
