// Generated on 2026-08-12T08:07:27.799Z by mcporter@0.9.0
// Server: openpencil
// Source: /root/.claude.json
// Transport: STDIO openpencil-mcp

import { createRuntime, createServerProxy, wrapCallResult } from 'mcporter';
import type { OpenpencilTools } from './openpencil-client.d';

type RuntimeInstance = Awaited<ReturnType<typeof createRuntime>>;
export type OpenpencilClient = OpenpencilTools & { close(): Promise<void> };

export interface CreateClientOptions {
  runtime?: RuntimeInstance;
  configPath?: string;
  rootDir?: string;
}

export async function createOpenpencilClient(options: CreateClientOptions = {}): Promise<OpenpencilClient> {
  const runtime = options.runtime ?? (await createRuntime({
    configPath: options.configPath,
    rootDir: options.rootDir,
  }));
  const ownsRuntime = !options.runtime;
  const proxy = createServerProxy(runtime, "openpencil");
  const client: OpenpencilClient = {
    async get_selection(params: Parameters<OpenpencilTools['get_selection']>[0]) {
      const tool = proxy.getSelection as (args: Parameters<OpenpencilTools['get_selection']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async get_node(params: Parameters<OpenpencilTools['get_node']>[0]) {
      const tool = proxy.getNode as (args: Parameters<OpenpencilTools['get_node']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async find_nodes(params: Parameters<OpenpencilTools['find_nodes']>[0]) {
      const tool = proxy.findNodes as (args: Parameters<OpenpencilTools['find_nodes']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async get_jsx(params: Parameters<OpenpencilTools['get_jsx']>[0]) {
      const tool = proxy.getJsx as (args: Parameters<OpenpencilTools['get_jsx']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async render(params: Parameters<OpenpencilTools['render']>[0]) {
      const tool = proxy.render as (args: Parameters<OpenpencilTools['render']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async update_node(params: Parameters<OpenpencilTools['update_node']>[0]) {
      const tool = proxy.updateNode as (args: Parameters<OpenpencilTools['update_node']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_layout(params: Parameters<OpenpencilTools['set_layout']>[0]) {
      const tool = proxy.setLayout as (args: Parameters<OpenpencilTools['set_layout']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_layout_child(params: Parameters<OpenpencilTools['set_layout_child']>[0]) {
      const tool = proxy.setLayoutChild as (args: Parameters<OpenpencilTools['set_layout_child']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_radius(params: Parameters<OpenpencilTools['set_radius']>[0]) {
      const tool = proxy.setRadius as (args: Parameters<OpenpencilTools['set_radius']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_fill(params: Parameters<OpenpencilTools['set_fill']>[0]) {
      const tool = proxy.setFill as (args: Parameters<OpenpencilTools['set_fill']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_stroke(params: Parameters<OpenpencilTools['set_stroke']>[0]) {
      const tool = proxy.setStroke as (args: Parameters<OpenpencilTools['set_stroke']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_text(params: Parameters<OpenpencilTools['set_text']>[0]) {
      const tool = proxy.setText as (args: Parameters<OpenpencilTools['set_text']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_text_properties(params: Parameters<OpenpencilTools['set_text_properties']>[0]) {
      const tool = proxy.setTextProperties as (args: Parameters<OpenpencilTools['set_text_properties']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async delete_node(params: Parameters<OpenpencilTools['delete_node']>[0]) {
      const tool = proxy.deleteNode as (args: Parameters<OpenpencilTools['delete_node']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async reparent_node(params: Parameters<OpenpencilTools['reparent_node']>[0]) {
      const tool = proxy.reparentNode as (args: Parameters<OpenpencilTools['reparent_node']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async node_resize(params: Parameters<OpenpencilTools['node_resize']>[0]) {
      const tool = proxy.nodeResize as (args: Parameters<OpenpencilTools['node_resize']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async batch_update(params: Parameters<OpenpencilTools['batch_update']>[0]) {
      const tool = proxy.batchUpdate as (args: Parameters<OpenpencilTools['batch_update']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async stock_photo(params: Parameters<OpenpencilTools['stock_photo']>[0]) {
      const tool = proxy.stockPhoto as (args: Parameters<OpenpencilTools['stock_photo']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async describe(params: Parameters<OpenpencilTools['describe']>[0]) {
      const tool = proxy.describe as (args: Parameters<OpenpencilTools['describe']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async calc(params: Parameters<OpenpencilTools['calc']>[0]) {
      const tool = proxy.calc as (args: Parameters<OpenpencilTools['calc']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async eval(params: Parameters<OpenpencilTools['eval']>[0]) {
      const tool = proxy.eval as (args: Parameters<OpenpencilTools['eval']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async viewport_zoom_to_fit(params: Parameters<OpenpencilTools['viewport_zoom_to_fit']>[0]) {
      const tool = proxy.viewportZoomToFit as (args: Parameters<OpenpencilTools['viewport_zoom_to_fit']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async get_page_tree(params: Parameters<OpenpencilTools['get_page_tree']>[0]) {
      const tool = proxy.getPageTree as (args: Parameters<OpenpencilTools['get_page_tree']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async get_current_page(params: Parameters<OpenpencilTools['get_current_page']>[0]) {
      const tool = proxy.getCurrentPage as (args: Parameters<OpenpencilTools['get_current_page']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async list_pages(params: Parameters<OpenpencilTools['list_pages']>[0]) {
      const tool = proxy.listPages as (args: Parameters<OpenpencilTools['list_pages']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async select_nodes(params: Parameters<OpenpencilTools['select_nodes']>[0]) {
      const tool = proxy.selectNodes as (args: Parameters<OpenpencilTools['select_nodes']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async query_nodes(params: Parameters<OpenpencilTools['query_nodes']>[0]) {
      const tool = proxy.queryNodes as (args: Parameters<OpenpencilTools['query_nodes']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async get_components(params: Parameters<OpenpencilTools['get_components']>[0]) {
      const tool = proxy.getComponents as (args: Parameters<OpenpencilTools['get_components']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async switch_page(params: Parameters<OpenpencilTools['switch_page']>[0]) {
      const tool = proxy.switchPage as (args: Parameters<OpenpencilTools['switch_page']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async page_bounds(params: Parameters<OpenpencilTools['page_bounds']>[0]) {
      const tool = proxy.pageBounds as (args: Parameters<OpenpencilTools['page_bounds']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async list_fonts(params: Parameters<OpenpencilTools['list_fonts']>[0]) {
      const tool = proxy.listFonts as (args: Parameters<OpenpencilTools['list_fonts']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async list_available_fonts(params: Parameters<OpenpencilTools['list_available_fonts']>[0]) {
      const tool = proxy.listAvailableFonts as (args: Parameters<OpenpencilTools['list_available_fonts']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async diff_jsx(params: Parameters<OpenpencilTools['diff_jsx']>[0]) {
      const tool = proxy.diffJsx as (args: Parameters<OpenpencilTools['diff_jsx']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async create_shape(params: Parameters<OpenpencilTools['create_shape']>[0]) {
      const tool = proxy.createShape as (args: Parameters<OpenpencilTools['create_shape']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async search_icons(params: Parameters<OpenpencilTools['search_icons']>[0]) {
      const tool = proxy.searchIcons as (args: Parameters<OpenpencilTools['search_icons']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async insert_icon(params: Parameters<OpenpencilTools['insert_icon']>[0]) {
      const tool = proxy.insertIcon as (args: Parameters<OpenpencilTools['insert_icon']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async fetch_icons(params: Parameters<OpenpencilTools['fetch_icons']>[0]) {
      const tool = proxy.fetchIcons as (args: Parameters<OpenpencilTools['fetch_icons']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async create_component(params: Parameters<OpenpencilTools['create_component']>[0]) {
      const tool = proxy.createComponent as (args: Parameters<OpenpencilTools['create_component']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async create_instance(params: Parameters<OpenpencilTools['create_instance']>[0]) {
      const tool = proxy.createInstance as (args: Parameters<OpenpencilTools['create_instance']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async create_page(params: Parameters<OpenpencilTools['create_page']>[0]) {
      const tool = proxy.createPage as (args: Parameters<OpenpencilTools['create_page']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async create_vector(params: Parameters<OpenpencilTools['create_vector']>[0]) {
      const tool = proxy.createVector as (args: Parameters<OpenpencilTools['create_vector']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async create_slice(params: Parameters<OpenpencilTools['create_slice']>[0]) {
      const tool = proxy.createSlice as (args: Parameters<OpenpencilTools['create_slice']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async import_svg(params: Parameters<OpenpencilTools['import_svg']>[0]) {
      const tool = proxy.importSvg as (args: Parameters<OpenpencilTools['import_svg']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_effects(params: Parameters<OpenpencilTools['set_effects']>[0]) {
      const tool = proxy.setEffects as (args: Parameters<OpenpencilTools['set_effects']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_opacity(params: Parameters<OpenpencilTools['set_opacity']>[0]) {
      const tool = proxy.setOpacity as (args: Parameters<OpenpencilTools['set_opacity']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_font(params: Parameters<OpenpencilTools['set_font']>[0]) {
      const tool = proxy.setFont as (args: Parameters<OpenpencilTools['set_font']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_visible(params: Parameters<OpenpencilTools['set_visible']>[0]) {
      const tool = proxy.setVisible as (args: Parameters<OpenpencilTools['set_visible']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_constraints(params: Parameters<OpenpencilTools['set_constraints']>[0]) {
      const tool = proxy.setConstraints as (args: Parameters<OpenpencilTools['set_constraints']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_rotation(params: Parameters<OpenpencilTools['set_rotation']>[0]) {
      const tool = proxy.setRotation as (args: Parameters<OpenpencilTools['set_rotation']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_minmax(params: Parameters<OpenpencilTools['set_minmax']>[0]) {
      const tool = proxy.setMinmax as (args: Parameters<OpenpencilTools['set_minmax']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_font_range(params: Parameters<OpenpencilTools['set_font_range']>[0]) {
      const tool = proxy.setFontRange as (args: Parameters<OpenpencilTools['set_font_range']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_text_resize(params: Parameters<OpenpencilTools['set_text_resize']>[0]) {
      const tool = proxy.setTextResize as (args: Parameters<OpenpencilTools['set_text_resize']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_blend(params: Parameters<OpenpencilTools['set_blend']>[0]) {
      const tool = proxy.setBlend as (args: Parameters<OpenpencilTools['set_blend']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_locked(params: Parameters<OpenpencilTools['set_locked']>[0]) {
      const tool = proxy.setLocked as (args: Parameters<OpenpencilTools['set_locked']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_stroke_align(params: Parameters<OpenpencilTools['set_stroke_align']>[0]) {
      const tool = proxy.setStrokeAlign as (args: Parameters<OpenpencilTools['set_stroke_align']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_image_fill(params: Parameters<OpenpencilTools['set_image_fill']>[0]) {
      const tool = proxy.setImageFill as (args: Parameters<OpenpencilTools['set_image_fill']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async clone_node(params: Parameters<OpenpencilTools['clone_node']>[0]) {
      const tool = proxy.cloneNode as (args: Parameters<OpenpencilTools['clone_node']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async node_move(params: Parameters<OpenpencilTools['node_move']>[0]) {
      const tool = proxy.nodeMove as (args: Parameters<OpenpencilTools['node_move']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async rename_node(params: Parameters<OpenpencilTools['rename_node']>[0]) {
      const tool = proxy.renameNode as (args: Parameters<OpenpencilTools['rename_node']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async group_nodes(params: Parameters<OpenpencilTools['group_nodes']>[0]) {
      const tool = proxy.groupNodes as (args: Parameters<OpenpencilTools['group_nodes']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async ungroup_node(params: Parameters<OpenpencilTools['ungroup_node']>[0]) {
      const tool = proxy.ungroupNode as (args: Parameters<OpenpencilTools['ungroup_node']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async flatten_nodes(params: Parameters<OpenpencilTools['flatten_nodes']>[0]) {
      const tool = proxy.flattenNodes as (args: Parameters<OpenpencilTools['flatten_nodes']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async node_to_component(params: Parameters<OpenpencilTools['node_to_component']>[0]) {
      const tool = proxy.nodeToComponent as (args: Parameters<OpenpencilTools['node_to_component']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async node_bounds(params: Parameters<OpenpencilTools['node_bounds']>[0]) {
      const tool = proxy.nodeBounds as (args: Parameters<OpenpencilTools['node_bounds']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async node_ancestors(params: Parameters<OpenpencilTools['node_ancestors']>[0]) {
      const tool = proxy.nodeAncestors as (args: Parameters<OpenpencilTools['node_ancestors']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async node_children(params: Parameters<OpenpencilTools['node_children']>[0]) {
      const tool = proxy.nodeChildren as (args: Parameters<OpenpencilTools['node_children']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async node_tree(params: Parameters<OpenpencilTools['node_tree']>[0]) {
      const tool = proxy.nodeTree as (args: Parameters<OpenpencilTools['node_tree']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async node_bindings(params: Parameters<OpenpencilTools['node_bindings']>[0]) {
      const tool = proxy.nodeBindings as (args: Parameters<OpenpencilTools['node_bindings']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async node_replace_with(params: Parameters<OpenpencilTools['node_replace_with']>[0]) {
      const tool = proxy.nodeReplaceWith as (args: Parameters<OpenpencilTools['node_replace_with']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async arrange(params: Parameters<OpenpencilTools['arrange']>[0]) {
      const tool = proxy.arrange as (args: Parameters<OpenpencilTools['arrange']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async list_variables(params: Parameters<OpenpencilTools['list_variables']>[0]) {
      const tool = proxy.listVariables as (args: Parameters<OpenpencilTools['list_variables']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async list_collections(params: Parameters<OpenpencilTools['list_collections']>[0]) {
      const tool = proxy.listCollections as (args: Parameters<OpenpencilTools['list_collections']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async get_variable(params: Parameters<OpenpencilTools['get_variable']>[0]) {
      const tool = proxy.getVariable as (args: Parameters<OpenpencilTools['get_variable']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async find_variables(params: Parameters<OpenpencilTools['find_variables']>[0]) {
      const tool = proxy.findVariables as (args: Parameters<OpenpencilTools['find_variables']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async create_variable(params: Parameters<OpenpencilTools['create_variable']>[0]) {
      const tool = proxy.createVariable as (args: Parameters<OpenpencilTools['create_variable']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async set_variable(params: Parameters<OpenpencilTools['set_variable']>[0]) {
      const tool = proxy.setVariable as (args: Parameters<OpenpencilTools['set_variable']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async delete_variable(params: Parameters<OpenpencilTools['delete_variable']>[0]) {
      const tool = proxy.deleteVariable as (args: Parameters<OpenpencilTools['delete_variable']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async bind_variable(params: Parameters<OpenpencilTools['bind_variable']>[0]) {
      const tool = proxy.bindVariable as (args: Parameters<OpenpencilTools['bind_variable']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async unbind_variable(params: Parameters<OpenpencilTools['unbind_variable']>[0]) {
      const tool = proxy.unbindVariable as (args: Parameters<OpenpencilTools['unbind_variable']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async get_collection(params: Parameters<OpenpencilTools['get_collection']>[0]) {
      const tool = proxy.getCollection as (args: Parameters<OpenpencilTools['get_collection']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async create_collection(params: Parameters<OpenpencilTools['create_collection']>[0]) {
      const tool = proxy.createCollection as (args: Parameters<OpenpencilTools['create_collection']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async delete_collection(params: Parameters<OpenpencilTools['delete_collection']>[0]) {
      const tool = proxy.deleteCollection as (args: Parameters<OpenpencilTools['delete_collection']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async boolean_union(params: Parameters<OpenpencilTools['boolean_union']>[0]) {
      const tool = proxy.booleanUnion as (args: Parameters<OpenpencilTools['boolean_union']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async boolean_subtract(params: Parameters<OpenpencilTools['boolean_subtract']>[0]) {
      const tool = proxy.booleanSubtract as (args: Parameters<OpenpencilTools['boolean_subtract']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async boolean_intersect(params: Parameters<OpenpencilTools['boolean_intersect']>[0]) {
      const tool = proxy.booleanIntersect as (args: Parameters<OpenpencilTools['boolean_intersect']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async boolean_exclude(params: Parameters<OpenpencilTools['boolean_exclude']>[0]) {
      const tool = proxy.booleanExclude as (args: Parameters<OpenpencilTools['boolean_exclude']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async path_get(params: Parameters<OpenpencilTools['path_get']>[0]) {
      const tool = proxy.pathGet as (args: Parameters<OpenpencilTools['path_get']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async path_set(params: Parameters<OpenpencilTools['path_set']>[0]) {
      const tool = proxy.pathSet as (args: Parameters<OpenpencilTools['path_set']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async path_scale(params: Parameters<OpenpencilTools['path_scale']>[0]) {
      const tool = proxy.pathScale as (args: Parameters<OpenpencilTools['path_scale']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async path_flip(params: Parameters<OpenpencilTools['path_flip']>[0]) {
      const tool = proxy.pathFlip as (args: Parameters<OpenpencilTools['path_flip']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async path_move(params: Parameters<OpenpencilTools['path_move']>[0]) {
      const tool = proxy.pathMove as (args: Parameters<OpenpencilTools['path_move']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async viewport_get(params: Parameters<OpenpencilTools['viewport_get']>[0]) {
      const tool = proxy.viewportGet as (args: Parameters<OpenpencilTools['viewport_get']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async viewport_set(params: Parameters<OpenpencilTools['viewport_set']>[0]) {
      const tool = proxy.viewportSet as (args: Parameters<OpenpencilTools['viewport_set']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async export_svg(params: Parameters<OpenpencilTools['export_svg']>[0]) {
      const tool = proxy.exportSvg as (args: Parameters<OpenpencilTools['export_svg']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async export_pdf(params: Parameters<OpenpencilTools['export_pdf']>[0]) {
      const tool = proxy.exportPdf as (args: Parameters<OpenpencilTools['export_pdf']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async export_image(params: Parameters<OpenpencilTools['export_image']>[0]) {
      const tool = proxy.exportImage as (args: Parameters<OpenpencilTools['export_image']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async analyze_colors(params: Parameters<OpenpencilTools['analyze_colors']>[0]) {
      const tool = proxy.analyzeColors as (args: Parameters<OpenpencilTools['analyze_colors']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async analyze_typography(params: Parameters<OpenpencilTools['analyze_typography']>[0]) {
      const tool = proxy.analyzeTypography as (args: Parameters<OpenpencilTools['analyze_typography']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async analyze_spacing(params: Parameters<OpenpencilTools['analyze_spacing']>[0]) {
      const tool = proxy.analyzeSpacing as (args: Parameters<OpenpencilTools['analyze_spacing']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async analyze_clusters(params: Parameters<OpenpencilTools['analyze_clusters']>[0]) {
      const tool = proxy.analyzeClusters as (args: Parameters<OpenpencilTools['analyze_clusters']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async analyze_overlaps(params: Parameters<OpenpencilTools['analyze_overlaps']>[0]) {
      const tool = proxy.analyzeOverlaps as (args: Parameters<OpenpencilTools['analyze_overlaps']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async diff_create(params: Parameters<OpenpencilTools['diff_create']>[0]) {
      const tool = proxy.diffCreate as (args: Parameters<OpenpencilTools['diff_create']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async diff_show(params: Parameters<OpenpencilTools['diff_show']>[0]) {
      const tool = proxy.diffShow as (args: Parameters<OpenpencilTools['diff_show']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async design_to_tokens(params: Parameters<OpenpencilTools['design_to_tokens']>[0]) {
      const tool = proxy.designToTokens as (args: Parameters<OpenpencilTools['design_to_tokens']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async design_to_component_map(params: Parameters<OpenpencilTools['design_to_component_map']>[0]) {
      const tool = proxy.designToComponentMap as (args: Parameters<OpenpencilTools['design_to_component_map']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async list_documents(params: Parameters<OpenpencilTools['list_documents']>[0]) {
      const tool = proxy.listDocuments as (args: Parameters<OpenpencilTools['list_documents']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async save_file(params: Parameters<OpenpencilTools['save_file']>[0]) {
      const tool = proxy.saveFile as (args: Parameters<OpenpencilTools['save_file']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async open_file(params: Parameters<OpenpencilTools['open_file']>[0]) {
      const tool = proxy.openFile as (args: Parameters<OpenpencilTools['open_file']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async new_document(params: Parameters<OpenpencilTools['new_document']>[0]) {
      const tool = proxy.newDocument as (args: Parameters<OpenpencilTools['new_document']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async get_codegen_prompt(params: Parameters<OpenpencilTools['get_codegen_prompt']>[0]) {
      const tool = proxy.getCodegenPrompt as (args: Parameters<OpenpencilTools['get_codegen_prompt']>[0]) => Promise<unknown>;
      const raw = await tool(params);
      return wrapCallResult(raw).callResult;
    },

    async close() {
      if (ownsRuntime) {
        await runtime.close("openpencil").catch(() => {});
      }
    },
  };
  return client;
}

