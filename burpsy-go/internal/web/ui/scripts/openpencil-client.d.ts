// Generated on 2026-08-12T08:07:27.799Z by mcporter@0.9.0
// Server: openpencil
// Source: /root/.claude.json
// Transport: STDIO openpencil-mcp

import type { CallResult } from 'mcporter';

export interface OpenpencilTools {
  /**
   * Get details about currently selected nodes.
   *
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  get_selection(document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get detailed properties of a node by ID. Use depth to limit child recursion (0 = node only, 1 =
   * direct children, etc). Default: unlimited.
   *
   * @param id Node ID
   * @param depth? Max depth of children to include (0 = no children). Default: unlimited
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  get_node(id: string, depth?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Find nodes by name pattern and/or type.
   *
   * @param name? Name substring to match (case-insensitive)
   * @param type? Node type filter
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  find_nodes(name?: string, type?: "FRAME" | "RECTANGLE" | "ELLIPSE" | "TEXT" | "LINE" | "STAR" | "POLYGON" | "SECTION" | "GROUP" | "COMPONENT" | "INSTANCE" | "VECTOR", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get JSX representation of a node and its children. Compact round-trip format — same syntax as the
   * render tool.
   *
   * @param id Node ID
   * @param path? Write JSX to this path instead of returning it (requires OPENPENCIL_MCP_ROOT)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  get_jsx(id: string, path?: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Render JSX to design nodes. Supports inline SVG paths, including open stroked paths: <svg viewBox="0
   * 0 24 24" size={24}><path d="M2 12 L22 12" stroke="#000" fill="none" /></svg>. Use replace_id to
   * replace a placeholder while preserving its position.
   *
   * @param replace_id? Node ID to replace — new node takes its position in parent, old node is deleted
   * @param parent_id? Parent node ID to render into
   * @param insert_index? Position among siblings (0 = first child). Omit to append at end.
   * @param x? X position of the root node
   * @param y? Y position of the root node
   * @param jsx JSX string to render
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  render(replace_id?: string, parent_id?: string, insert_index?: number, x?: number, jsx: string): Promise<CallResult>;
  // optional (3): y, document_id, page_id

  /**
   * Update properties of an existing node: position, size, opacity, corner radius, visibility, text,
   * font.
   *
   * @param id Node ID
   * @param x? X position
   * @param y? Y position
   * @param width? Width
   * @param height? Height
   * @param opacity? Opacity (0-1)
   * @param corner_radius? Corner radius
   * @param visible? Visibility
   * @param text? Text content (TEXT nodes)
   * @param text_direction? Text direction for TEXT nodes
   * @param flow_direction? Auto-layout flow direction for FRAME nodes
   * @param font_size? Font size
   * @param font_weight? Font weight (100-900)
   * @param name? Layer name
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  update_node(id: string, x?: number, y?: number, width?: number, height?: number): Promise<CallResult>;
  // optional (11): opacity, corner_radius, visible, text, text_direction, ...

  /**
   * Set auto-layout (flexbox) on a frame. Direction, alignment, spacing, padding.
   *
   * @param id Frame node ID
   * @param direction? Layout direction (keeps current if omitted)
   * @param spacing? Gap between items (only changes if provided)
   * @param padding? Equal padding on all sides (only changes if provided)
   * @param padding_horizontal? Horizontal padding
   * @param padding_vertical? Vertical padding
   * @param align? Primary axis alignment (only changes if provided)
   * @param counter_align? Cross axis alignment (only changes if provided)
   * @param flow_direction? Child flow direction for auto-layout. AUTO inherits from parent.
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_layout(id: string, direction?: "HORIZONTAL" | "VERTICAL", spacing?: number, padding?: number, padding_horizontal?: number): Promise<CallResult>;
  // optional (6): padding_vertical, align, counter_align, flow_direction, document_id, ...

  /**
   * Configure auto-layout child: sizing (FIXED/HUG/FILL), grow, alignment, absolute positioning.
   *
   * @param id Child node ID
   * @param sizing_horizontal? Horizontal sizing mode
   * @param sizing_vertical? Vertical sizing mode
   * @param grow? Flex grow factor (0 = fixed, 1 = grow)
   * @param align_self? Self alignment override (cross-axis)
   * @param positioning? ABSOLUTE to take node out of auto-layout flow
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_layout_child(id: string, sizing_horizontal?: "FIXED" | "HUG" | "FILL", sizing_vertical?: "FIXED" | "HUG" | "FILL", grow?: number, align_self?: "INHERIT" | "MIN" | "CENTER" | "MAX" | "STRETCH" | "BASELINE"): Promise<CallResult>;
  // optional (3): positioning, document_id, page_id

  /**
   * Set corner radius. Use individual corners for independent values.
   *
   * @param id Node ID
   * @param radius? Corner radius for all corners
   * @param top_left? Top-left radius
   * @param top_right? Top-right radius
   * @param bottom_right? Bottom-right radius
   * @param bottom_left? Bottom-left radius
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_radius(id: string, radius?: number, top_left?: number, top_right?: number, bottom_right?: number): Promise<CallResult>;
  // optional (3): bottom_left, document_id, page_id

  /**
   * Set fill on a node. Solid: color="#ff0000". Linear gradient: gradient="top-bottom" or "left-right"
   * with color (start) and color_end (end).
   *
   * @param id Node ID
   * @param color Color (hex). For gradient: start color.
   * @param color_end? End color for gradient (if omitted, solid fill)
   * @param gradient? Gradient direction
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_fill(id: string, color: string, color_end?: string, gradient?: "top-bottom" | "bottom-top" | "left-right" | "right-left", document_id?: string): Promise<CallResult>;
  // optional (1): page_id

  /**
   * Set the stroke (border) of a node.
   *
   * @param id Node ID
   * @param color Stroke color (hex)
   * @param weight? Stroke weight
   * @param align? Stroke alignment
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_stroke(id: string, color: string, weight?: number, align?: "INSIDE" | "CENTER" | "OUTSIDE", document_id?: string): Promise<CallResult>;
  // optional (1): page_id

  /**
   * Set text content of a text node.
   *
   * @param id Node ID
   * @param text Text content
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_text(id: string, text: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set text layout properties: alignment, auto-resize, text case, decoration, truncation.
   *
   * @param id Text node ID
   * @param align_horizontal? Horizontal text alignment
   * @param align_vertical? Vertical text alignment
   * @param auto_resize? Text auto-resize mode
   * @param direction? Text direction
   * @param text_decoration? Text decoration
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_text_properties(id: string, align_horizontal?: "LEFT" | "CENTER" | "RIGHT" | "JUSTIFIED", align_vertical?: "TOP" | "CENTER" | "BOTTOM", auto_resize?: "NONE" | "WIDTH_AND_HEIGHT" | "HEIGHT" | "TRUNCATE", direction?: "AUTO" | "LTR" | "RTL"): Promise<CallResult>;
  // optional (3): text_decoration, document_id, page_id

  /**
   * Delete a node by ID.
   *
   * @param id Node ID to delete
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  delete_node(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Move a node into a different parent.
   *
   * @param id Node ID to move
   * @param parent_id New parent node ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  reparent_node(id: string, parent_id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Resize a node.
   *
   * @param id Node ID
   * @param width Width
   * @param height Height
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  node_resize(id: string, width: number, height: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Execute multiple modifications in one call. Each operation is {id, props} where props can include:
   * spacing, padding, padding_horizontal, padding_vertical, counter_align, sizing_horizontal,
   * sizing_vertical, grow, name, visible, corner_radius, auto_resize (for text), direction. Runs all
   * updates with one layout recompute.
   *
   * @param operations JSON array:
   *                   [{"id":"0:5","props":{"spacing":8}},{"id":"0:6","props":{"sizing_horizontal":"FILL","grow":1}}]
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  batch_update(operations: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Search stock photos and apply to nodes. Pass a JSON array — all fetched in parallel. Each item: {id,
   * query, index?, orientation?}. Only works on leaf shapes (Rectangle/Ellipse).
   *
   * @param requests JSON array: [{"id":"0:5","query":"mountain sunset"},{"id":"0:8","query":"business
   *                 team","orientation":"square"}]
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  stock_photo(requests: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Semantic description of one or more nodes. Pass `id` for a single node, or `ids` for multiple nodes
   * in one call. Omit depth for auto — adapts to subtree size (small block → deeper, large page →
   * shallower).
   *
   * @param id? Node ID (single node)
   * @param ids? Node IDs (multiple nodes in one call)
   * @param depth? Override depth (auto if omitted, max: 5)
   * @param grid? Grid size for alignment checks (default: 8)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  describe(id?: string, ids?: string[], depth?: number, grid?: number, document_id?: string): Promise<CallResult>;
  // optional (1): page_id

  /**
   * Arithmetic calculator. ALWAYS use instead of mental math. Pass one expression or a JSON array of
   * expressions — all evaluated in one call. Supports: + - * / % ** ( ) min max floor ceil round abs
   * sqrt pow. Examples: "844 - 56 - 96 - 82", '["1440 * 8 / 12", "(952 - 16) / 2", "floor(390 * 0.6)"]'
   *
   * @param expr Single expression or JSON array of expressions
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  calc(expr: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Execute JavaScript with full Figma Plugin API access. Use for operations not covered by other tools.
   * The `figma` global is available.
   *
   * @param code JavaScript code to execute
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  eval(code: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Zoom viewport to fit specified nodes.
   *
   * @param ids Node IDs to fit in view
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  viewport_zoom_to_fit(ids: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get the node tree of the current page. Returns lightweight hierarchy: id, type, name, size. Use
   * depth, root_id, or node_types to keep large pages small. Use get_node for full properties of a
   * specific node.
   *
   * @param depth? Max nesting depth to return (1 = returned root nodes only). Default: unlimited
   * @param root_id? Return only this node subtree instead of the whole current page
   * @param node_types? Keep only these node types and their ancestors, for example FRAME or TEXT
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  get_page_tree(depth?: number, root_id?: string, node_types?: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get the current page name and ID.
   *
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  get_current_page(document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * List all pages in the document.
   *
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  list_pages(document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Select one or more nodes by ID.
   *
   * @param ids Node IDs to select
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  select_nodes(ids: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Query nodes using XPath selectors. Node types are element names (FRAME, TEXT, RECTANGLE, ELLIPSE,
   * etc.). Attributes: name, width, height, x, y, visible, opacity, cornerRadius, fontSize, fontFamily,
   * fontWeight, layoutMode, itemSpacing, paddingTop/Right/Bottom/Left, strokeWeight, rotation, locked,
   * blendMode, text, lineHeight, letterSpacing.
   * Examples:
   * //FRAME — all frames
   * //FRAME[@width < 300] — frames narrower than 300px
   * //COMPONENT[starts-with(@name, 'Button')] — components starting with "Button"
   * //SECTION/FRAME — direct frame children of sections
   * //SECTION//TEXT — all text nodes inside sections
   * //*[@cornerRadius > 0] — any node with corner radius
   * //TEXT[contains(@text, 'Hello')] — text nodes containing "Hello"
   *
   * @param selector XPath selector
   * @param page? Page name (default: current page)
   * @param limit? Max results (default: 1000)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  query_nodes(selector: string, page?: string, limit?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * List all components in the document, optionally filtered by name.
   *
   * @param name? Filter by name (case-insensitive substring)
   * @param limit? Max results (default: 50)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  get_components(name?: string, limit?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Switch to a different page by name or ID.
   *
   * @param page Page name or ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  switch_page(page: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get bounding box of all objects on the current page.
   *
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  page_bounds(document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * List fonts used in the current page.
   *
   * @param family? Filter by family name (substring)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  list_fonts(family?: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * List font families the host can render (system fonts on desktop plus any bundled fonts). Use this to
   * discover what fonts are available to set on a text node — distinct from list_fonts which only
   * reports families currently used in the page.
   *
   * @param family? Filter by family name (substring, case-insensitive)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  list_available_fonts(family?: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Structural diff between two nodes in JSX format. Shows added/removed children, changed props.
   *
   * @param from Source node ID
   * @param to Target node ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  diff_jsx(from: string, to: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Create a shape on the canvas. Use FRAME for containers/cards, RECTANGLE for solid blocks, ELLIPSE
   * for circles, TEXT for labels, LINE for rules and dividers, STAR for starbursts and badges, POLYGON
   * for triangles and regular polygons, and SECTION for page sections. Use create_vector with an SVG
   * path for arbitrary shapes.
   *
   * @param type Node type
   * @param x X position
   * @param y Y position
   * @param width Width in pixels
   * @param height Height in pixels
   * @param name? Node name shown in layers panel
   * @param parent_id? Parent node ID to nest inside
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  create_shape(type: "FRAME" | "RECTANGLE" | "ELLIPSE" | "TEXT" | "LINE" | "STAR" | "POLYGON" | "SECTION", x: number, y: number, width: number, height: number): Promise<CallResult>;
  // optional (4): name, parent_id, document_id, page_id

  /**
   * Search Iconify for icons by keyword. Accepts multiple queries — all searched in parallel. Returns
   * results keyed by query.
   *
   * @param queries Search keywords (e.g. ["heart", "arrow", "settings"])
   * @param limit? Max results per query (default: 5)
   * @param prefix? Filter by icon set prefix (e.g. "lucide", "mdi")
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  search_icons(queries: string[], limit?: number, prefix?: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Insert one or more vector icons onto the canvas. Pass a single name or multiple names to
   * batch-insert into the same parent. If already cached by fetch_icons — instant, no network request.
   *
   * @param names? Icon names as prefix:name (e.g. ["lucide:heart"] or
   *               ["lucide:heart","lucide:home","lucide:star"])
   * @param name? Single icon name (shorthand for names with one icon)
   * @param size? Icon size in pixels (default: 24)
   * @param color? Icon color hex (replaces currentColor). Default: #000000
   * @param parent_id? Parent node ID for all icons
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  insert_icon(names?: string[], name?: string, size?: number, color?: string, parent_id?: string): Promise<CallResult>;
  // optional (2): document_id, page_id

  /**
   * Pre-fetch icons from Iconify into cache. Batches by prefix (one HTTP request per set). Call this
   * once with all needed icons, then use insert_icon to place them instantly. Popular sets: lucide
   * (outline), mdi (filled), heroicons, tabler, solar, mingcute, ri (remix).
   *
   * @param names Icon names as prefix:name (e.g. ["lucide:heart", "lucide:home", "mdi:star"])
   * @param size? Icon size in pixels (default: 24)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  fetch_icons(names: string[], size?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Convert a frame/group into a component.
   *
   * @param id Node ID to convert
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  create_component(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Create an instance of a component.
   *
   * @param component_id Component node ID
   * @param x? X position
   * @param y? Y position
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  create_instance(component_id: string, x?: number, y?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Create a new page.
   *
   * @param name Page name
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  create_page(name: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Create a vector node from SVG path data or a VectorNetwork.
   *
   * @param x X position
   * @param y Y position
   * @param name? Node name
   * @param path? SVG path data (preferred, e.g. "M0 0 L100 0 L50 80 Z") or VectorNetwork JSON, e.g.
   *              {"vertices":[{"x":0,"y":0},{"x":10,"y":0}],"segments":[{"start":0,"end":1}],"regions":[]}
   * @param fill? Fill color (hex)
   * @param stroke? Stroke color (hex)
   * @param stroke_weight? Stroke weight
   * @param parent_id? Parent node ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  create_vector(x: number, y: number, name?: string, path?: string, fill?: string): Promise<CallResult>;
  // optional (5): stroke, stroke_weight, parent_id, document_id, page_id

  /**
   * Create a slice (export region) on the canvas.
   *
   * @param x X position
   * @param y Y position
   * @param width Width
   * @param height Height
   * @param name? Slice name
   * @param parent_id? Parent node ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  create_slice(x: number, y: number, width: number, height: number, name?: string): Promise<CallResult>;
  // optional (3): parent_id, document_id, page_id

  /**
   * Import raw SVG markup onto the canvas as editable vector nodes. Supports common SVG shapes,
   * inherited presentation attributes, transforms, gradients, and internal <use> references.
   *
   * @param svg SVG markup string (e.g. '<svg viewBox="0 0 24 24"><path d="M..."/></svg>')
   * @param name? Name for the created frame (default: "SVG")
   * @param color? Default color for currentColor fills/strokes (default: #000000)
   * @param parent_id? Parent node ID
   * @param x? X position
   * @param y? Y position
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  import_svg(svg: string, name?: string, color?: string, parent_id?: string, x?: number): Promise<CallResult>;
  // optional (3): y, document_id, page_id

  /**
   * Set effects on a node (drop shadow, inner shadow, blur). Pass an array or a single effect.
   *
   * @param id Node ID
   * @param type Effect type
   * @param color? Shadow color (hex). Ignored for blur.
   * @param offset_x? Shadow X offset
   * @param offset_y? Shadow Y offset
   * @param radius? Blur radius
   * @param spread? Shadow spread
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_effects(id: string, type: "DROP_SHADOW" | "INNER_SHADOW" | "FOREGROUND_BLUR" | "BACKGROUND_BLUR", color?: string, offset_x?: number, offset_y?: number): Promise<CallResult>;
  // optional (4): radius, spread, document_id, page_id

  /**
   * Set opacity of a node (0-1).
   *
   * @param id Node ID
   * @param value Opacity (0-1)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_opacity(id: string, value: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set font properties of a text node.
   *
   * @param id Node ID
   * @param family? Font family name
   * @param size? Font size
   * @param style? Font style (e.g. "Bold", "Regular", "Bold Italic")
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_font(id: string, family?: string, size?: number, style?: string, document_id?: string): Promise<CallResult>;
  // optional (1): page_id

  /**
   * Set visibility of a node.
   *
   * @param id Node ID
   * @param value Visible (true/false)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_visible(id: string, value: boolean, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set resize constraints for a node within its parent.
   *
   * @param id Node ID
   * @param horizontal? Horizontal constraint
   * @param vertical? Vertical constraint
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_constraints(id: string, horizontal?: "MIN" | "CENTER" | "MAX" | "STRETCH" | "SCALE", vertical?: "MIN" | "CENTER" | "MAX" | "STRETCH" | "SCALE", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set rotation angle of a node in degrees.
   *
   * @param id Node ID
   * @param angle Rotation angle in degrees
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_rotation(id: string, angle: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set min/max width and height constraints on a node.
   *
   * @param id Node ID
   * @param min_width? Minimum width
   * @param max_width? Maximum width
   * @param min_height? Minimum height
   * @param max_height? Maximum height
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_minmax(id: string, min_width?: number, max_width?: number, min_height?: number, max_height?: number): Promise<CallResult>;
  // optional (2): document_id, page_id

  /**
   * Set font properties for a text range.
   *
   * @param id Node ID
   * @param start Start character index
   * @param end End character index
   * @param family? Font family name
   * @param size? Font size
   * @param style? Font style
   * @param color? Text color (hex)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_font_range(id: string, start: number, end: number, family?: string, size?: number): Promise<CallResult>;
  // optional (4): style, color, document_id, page_id

  /**
   * Set text auto-resize mode.
   *
   * @param id Node ID
   * @param mode Resize mode
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_text_resize(id: string, mode: "NONE" | "WIDTH_AND_HEIGHT" | "HEIGHT" | "TRUNCATE", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set blend mode of a node.
   *
   * @param id Node ID
   * @param mode Blend mode
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_blend(id: string, mode: "NORMAL" | "DARKEN" | "MULTIPLY" | "COLOR_BURN" | "LIGHTEN" | "SCREEN" | "COLOR_DODGE" | "OVERLAY" | "SOFT_LIGHT" | "HARD_LIGHT" | "DIFFERENCE" | "EXCLUSION" | "HUE" | "SATURATION" | "COLOR" | "LUMINOSITY", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set locked state of a node.
   *
   * @param id Node ID
   * @param value Locked (true/false)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_locked(id: string, value: boolean, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set stroke alignment of a node.
   *
   * @param id Node ID
   * @param align Stroke alignment
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_stroke_align(id: string, align: "INSIDE" | "CENTER" | "OUTSIDE", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set an image fill on a node from base64-encoded image data.
   *
   * @param id Node ID
   * @param image_data Base64-encoded image bytes (PNG, JPEG, or WEBP)
   * @param scale_mode? Image scale mode
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_image_fill(id: string, image_data: string, scale_mode?: "FILL" | "FIT" | "CROP" | "TILE", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Clone (duplicate) a node.
   *
   * @param id Node ID to clone
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  clone_node(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Move a node to new coordinates.
   *
   * @param id Node ID
   * @param x X position
   * @param y Y position
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  node_move(id: string, x: number, y: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Rename a node in the layers panel.
   *
   * @param id Node ID
   * @param name New name
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  rename_node(id: string, name: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Group selected nodes.
   *
   * @param ids Node IDs to group
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  group_nodes(ids: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Ungroup a group node.
   *
   * @param id Group node ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  ungroup_node(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Flatten nodes into a single vector.
   *
   * @param ids Node IDs to flatten
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  flatten_nodes(ids: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Convert one or more frames/groups into components.
   *
   * @param ids Node IDs to convert
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  node_to_component(ids: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get absolute bounding box of a node.
   *
   * @param id Node ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  node_bounds(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get the ancestor chain from a node to the page root.
   *
   * @param id Node ID
   * @param depth? Max depth to traverse
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  node_ancestors(id: string, depth?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get direct children of a node.
   *
   * @param id Node ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  node_children(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get a node tree with types and hierarchy.
   *
   * @param id Node ID
   * @param depth? Max depth (default: unlimited)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  node_tree(id: string, depth?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get variable bindings for a node.
   *
   * @param id Node ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  node_bindings(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Replace a node with JSX content.
   *
   * @param id Node ID to replace
   * @param jsx JSX string for the replacement
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  node_replace_with(id: string, jsx: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Arrange top-level nodes on the canvas in a grid, row, or column layout. Useful after batch creation
   * to tidy up overlapping frames.
   *
   * @param ids? Node IDs to arrange (default: all top-level children)
   * @param mode? Layout mode
   * @param gap? Spacing between nodes (default: 40)
   * @param cols? Column count for grid mode (default: auto)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  arrange(ids?: string[], mode?: "grid" | "row" | "column", gap?: number, cols?: number, document_id?: string): Promise<CallResult>;
  // optional (1): page_id

  /**
   * List all design variables (colors, numbers, strings, booleans).
   *
   * @param type? Filter by variable type
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  list_variables(type?: "COLOR" | "FLOAT" | "STRING" | "BOOLEAN", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * List all variable collections.
   *
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  list_collections(document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get a variable by ID.
   *
   * @param id Variable ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  get_variable(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Find variables by name pattern.
   *
   * @param query Name substring (case-insensitive)
   * @param type? Filter by type
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  find_variables(query: string, type?: "COLOR" | "FLOAT" | "STRING" | "BOOLEAN", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Create a new variable in a collection.
   *
   * @param name Variable name
   * @param type Variable type
   * @param collection_id Collection ID
   * @param value? Initial value (hex for COLOR, number for FLOAT, etc.)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  create_variable(name: string, type: "COLOR" | "FLOAT" | "STRING" | "BOOLEAN", collection_id: string, value?: string, document_id?: string): Promise<CallResult>;
  // optional (1): page_id

  /**
   * Set the value of a variable for a specific mode.
   *
   * @param id Variable ID
   * @param mode Mode ID
   * @param value Value (hex for COLOR, number for FLOAT, etc.)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  set_variable(id: string, mode: string, value: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Delete a variable.
   *
   * @param id Variable ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  delete_variable(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Bind a variable to a node property. For fills/strokes color bindings use indexed format like
   * "fills/0/color".
   *
   * @param node_id Node ID
   * @param field Property field path. For fills/strokes use indexed format: "fills/0/color",
   *              "strokes/0/color". For FLOAT scalars: "opacity", "width", "height", "cornerRadius",
   *              "fontSize", "letterSpacing", "lineHeight", "itemSpacing", "strokeWeight",
   *              "paddingLeft/Right/Top/Bottom", "counterAxisSpacing", "rotation", "x", "y", "minWidth",
   *              "maxWidth", "minHeight", "maxHeight", "topLeftRadius", "topRightRadius",
   *              "bottomLeftRadius", "bottomRightRadius", "borderTopWeight", "borderBottomWeight",
   *              "borderLeftWeight", "borderRightWeight", "gridRowGap", "gridColumnGap". For STRING:
   *              "fontFamily". For BOOLEAN: "visible".
   * @param variable_id Variable ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  bind_variable(node_id: string, field: string, variable_id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Remove a variable binding from a node property.
   *
   * @param node_id Node ID
   * @param field Property field path to unbind. For fills/strokes use indexed format: "fills/0/color",
   *              "strokes/0/color". For FLOAT scalars: "opacity", "width", "height", "cornerRadius",
   *              "fontSize", "letterSpacing", "lineHeight", "itemSpacing", "strokeWeight",
   *              "paddingLeft/Right/Top/Bottom", "counterAxisSpacing", "rotation", "x", "y", "minWidth",
   *              "maxWidth", "minHeight", "maxHeight", "topLeftRadius", "topRightRadius",
   *              "bottomLeftRadius", "bottomRightRadius", "borderTopWeight", "borderBottomWeight",
   *              "borderLeftWeight", "borderRightWeight", "gridRowGap", "gridColumnGap". For STRING:
   *              "fontFamily". For BOOLEAN: "visible".
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  unbind_variable(node_id: string, field: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get a variable collection by ID.
   *
   * @param id Collection ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  get_collection(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Create a new variable collection.
   *
   * @param name Collection name
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  create_collection(name: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Delete a variable collection and all its variables.
   *
   * @param id Collection ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  delete_collection(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Union (combine) multiple nodes.
   *
   * @param ids Node IDs to union
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  boolean_union(ids: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Subtract the second node from the first.
   *
   * @param ids Node IDs (first minus rest)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  boolean_subtract(ids: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Intersect multiple nodes.
   *
   * @param ids Node IDs to intersect
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  boolean_intersect(ids: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Exclude (XOR) multiple nodes.
   *
   * @param ids Node IDs to exclude
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  boolean_exclude(ids: string[], document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get vector path data of a node.
   *
   * @param id Node ID
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  path_get(id: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set vector path data on a node. Provide a VectorNetwork JSON.
   *
   * @param id Node ID
   * @param path VectorNetwork JSON
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  path_set(id: string, path: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Scale vector path from center.
   *
   * @param id Node ID
   * @param factor Scale factor (e.g. 2 for double)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  path_scale(id: string, factor: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Flip vector path horizontally or vertically.
   *
   * @param id Node ID
   * @param axis Flip axis
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  path_flip(id: string, axis: "horizontal" | "vertical", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Move all path points by an offset.
   *
   * @param id Node ID
   * @param dx X offset
   * @param dy Y offset
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  path_move(id: string, dx: number, dy: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get current viewport position and zoom level.
   *
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  viewport_get(document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Set viewport position and zoom.
   *
   * @param x Center X
   * @param y Center Y
   * @param zoom Zoom level
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  viewport_set(x: number, y: number, zoom: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Export nodes as SVG markup. Returns the SVG string.
   *
   * @param ids? Node IDs to export. Omit to export all top-level nodes on the current page.
   * @param path? Write SVG to this path instead of returning it (requires OPENPENCIL_MCP_ROOT)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  export_svg(ids?: string[], path?: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Export nodes as a vector PDF document. Text remains selectable, paths stay sharp at any zoom.
   * Returns base64-encoded PDF data.
   *
   * @param ids? Node IDs to export. Omit to export all top-level nodes on the current page.
   * @param path? Write PDF to this path instead of returning base64 (requires OPENPENCIL_MCP_ROOT)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  export_pdf(ids?: string[], path?: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Export nodes as a raster image (PNG, JPG, or WEBP). Returns base64-encoded image data. Use to
   * visually verify designs.
   *
   * @param ids? Node IDs to export. Omit to export all top-level nodes on the current page.
   * @param format? Image format
   * @param scale? Export scale multiplier (default: 1)
   * @param path? Write image to this path instead of returning base64 (requires OPENPENCIL_MCP_ROOT)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  export_image(ids?: string[], format?: "PNG" | "JPG" | "WEBP", scale?: number, path?: string, document_id?: string): Promise<CallResult>;
  // optional (1): page_id

  /**
   * Analyze color palette usage across the current page. Shows frequency, variable bindings, and
   * optionally clusters similar colors.
   *
   * @param limit? Max colors to return (default: 30)
   * @param show_similar? Include similar-color clusters for potential merging
   * @param threshold? Distance threshold for clustering (0-50, default: 15)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  analyze_colors(limit?: number, show_similar?: boolean, threshold?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Analyze typography usage across the current page. Shows font families, sizes, weights, and their
   * frequencies.
   *
   * @param limit? Max styles to return (default: 30)
   * @param group_by? Group results by a property
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  analyze_typography(limit?: number, group_by?: "family" | "size" | "weight", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Analyze spacing values (gap, padding) across the current page. Checks grid compliance.
   *
   * @param grid? Base grid size to check against (default: 8)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  analyze_spacing(grid?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Find repeated design patterns (potential components). Groups nodes by structural signature — type,
   * size, and child structure.
   *
   * @param min_count? Min instances to form a cluster (default: 2)
   * @param min_size? Min node size in px (default: 30)
   * @param limit? Max clusters to return (default: 20)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  analyze_clusters(min_count?: number, min_size?: number, limit?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Detect visual overlaps and layout overflows across the current page. Useful for finding content that
   * covers footers, text that bleeds outside frames, and accidental sibling overlaps.
   *
   * @param scope? Which pairs to inspect: all, same-parent, cross-parent, top-level, inside-parent
   *               (default: all)
   * @param category? Comma-separated categories: sibling-overlap, parent-overflow, overlay (default:
   *                  all)
   * @param severity? Minimum severity to include: critical, major, minor, info (default: info)
   * @param min_area? Minimum overlap area in square pixels (default: 0)
   * @param min_ratio? Minimum overlap ratio relative to the smaller node, 0.0–1.0 (default: 0)
   * @param include_hidden? Include hidden nodes in the analysis
   * @param include_locked? Include locked nodes in the analysis
   * @param include_absolute? Include absolutely-positioned nodes in the analysis
   * @param page? Limit analysis to nodes on the named page
   * @param page_id? Optional page ID to target within the document
   * @param type? Comma-separated node types to analyze, e.g. FRAME,TEXT
   * @param limit? Maximum overlap findings to return (default: 100)
   * @param document_id? Optional OpenPencil document/tab ID to target
   */
  analyze_overlaps(scope?: "all" | "same-parent" | "cross-parent" | "top-level" | "inside-parent", category?: string, severity?: "critical" | "major" | "minor" | "info", min_area?: number, min_ratio?: number): Promise<CallResult>;
  // optional (8): include_hidden, include_locked, include_absolute, page, page_id, ...

  /**
   * Create a structural diff between two node trees. Compares properties (fills, strokes, effects, text,
   * size, position) in unified diff format.
   *
   * @param from Source node ID
   * @param to Target node ID
   * @param depth? Max tree depth (default: 10)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  diff_create(from: string, to: string, depth?: number, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Preview what would change if properties were applied to a node. Shows a unified diff of current vs
   * proposed state.
   *
   * @param id Node ID
   * @param props JSON object of new properties, e.g. '{"opacity": 1, "fill": "#FF0000", "width": 200}'
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  diff_show(id: string, props: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Extract design tokens from Figma variables as CSS custom properties, Tailwind theme config, or JSON.
   * Resolves aliases, handles multiple modes (light/dark).
   *
   * @param format? Output format
   * @param collection? Filter by collection name (substring, case-insensitive)
   * @param type? Filter by variable type
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  design_to_tokens(format?: "css" | "tailwind" | "json", collection?: string, type?: "COLOR" | "FLOAT" | "STRING" | "BOOLEAN", document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Analyze the document and return a structured component decomposition: components (with variants,
   * props, instance counts), screens, and a dependency overview.
   *
   * @param page? Page name to analyze (default: current page)
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  design_to_component_map(page?: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * List open OpenPencil documents/tabs with their IDs, file paths, current pages, and pages.
   */
  list_documents(): Promise<CallResult>;

  /**
   * Save the current document to disk. If path is provided, it must be inside /root.
   *
   * @param path? Path for the .fig file, absolute or relative to the MCP root
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  save_file(path?: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Open a .fig or .pen file from disk into a new tab. Path must be inside /root.
   *
   * @param path Path to the design file, absolute or relative to the MCP root
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  open_file(path: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Create a new empty document. Optionally set a save path inside /root.
   *
   * @param path? Path for the new file, absolute or relative to the MCP root
   * @param document_id? Optional OpenPencil document/tab ID to target
   * @param page_id? Optional page ID to target within the document
   */
  new_document(path?: string, document_id?: string, page_id?: string): Promise<CallResult>;

  /**
   * Get design-to-code generation guidelines. Call before generating frontend code.
   */
  get_codegen_prompt(): Promise<CallResult>;
}

