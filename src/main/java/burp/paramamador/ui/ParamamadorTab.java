package burp.paramamador.ui;

import burp.paramamador.Settings;
import burp.paramamador.datastore.DataStore;
import burp.paramamador.datastore.EndpointRecord;
import burp.paramamador.datastore.ParameterRecord;
import burp.paramamador.integrations.JsluiceService;
import burp.paramamador.integrations.JsluiceUrlRecord;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.nio.file.Path;
import java.util.List;
import java.util.*;
import java.util.regex.Pattern;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 * Main suite tab containing three sub-tabs: Parameters, Endpoints, Settings.
 */
public class ParamamadorTab {
    private final DataStore store;
    private final Settings settings;
    private final Runnable rescanAction;
    private final Runnable saveAction;
    private final JsluiceService jsluiceService;
    private final java.util.function.Consumer<HttpRequest> repeaterSender;
    private final java.util.function.Function<String,String> lastAuthFinder;
    private final java.util.function.Function<String,String> lastCookieFinder;
    private final java.util.function.Function<String, java.util.List<String>> siteMapUrlsByHostFetcher;
    private final java.util.function.Function<String, java.util.Map<String,String>> latestAuthCookieFinder;

    private final JPanel root = new JPanel(new BorderLayout());

    // Parameters
    private final ParameterTableModel paramModel;
    private final JTable paramTable = new JTable();
    private final TableRowSorter<ParameterTableModel> paramSorter = new TableRowSorter<>();

    // Endpoints
    private final EndpointTableModel endpointModel;
    private final JTable endpointTable = new JTable();
    private final TableRowSorter<EndpointTableModel> endpointSorter = new TableRowSorter<>();
    private final JTextArea endpointContext = new JTextArea();

    // NotSure endpoints
    private final EndpointTableModel notSureModel;
    private final JTable notSureTable = new JTable();
    private final TableRowSorter<EndpointTableModel> notSureSorter = new TableRowSorter<>();
    private final JTextArea notSureContext = new JTextArea();

    // jsluice results
    private final JsluiceTableModel jsluiceModel;
    private final JTable jsluiceTable = new JTable();
    private final javax.swing.table.TableRowSorter<JsluiceTableModel> jsluiceSorter = new javax.swing.table.TableRowSorter<>();

    // Settings controls
    private final JCheckBox scopeOnly = new JCheckBox("Scope only");
    private final JSpinner autoSaveSec = new JSpinner(new SpinnerNumberModel(300, 30, 3600, 10));
    private final JSpinner maxInlineKb = new JSpinner(new SpinnerNumberModel(200, 10, 10_000, 10));
    private final JSpinner maxQueue = new JSpinner(new SpinnerNumberModel(200, 50, 10_000, 10));
    private final JTextField exportDir = new JTextField();
    private final DefaultListModel<String> ignoredModel = new DefaultListModel<>();
    private final DefaultListModel<String> varDefaultsModel = new DefaultListModel<>();
    private final DefaultListModel<String> defaultHeadersModel = new DefaultListModel<>();

    public ParamamadorTab(DataStore store, Settings settings, Runnable rescanAction, Runnable saveAction, JsluiceService jsluiceService, java.util.function.Consumer<HttpRequest> repeaterSender,
                          java.util.function.Function<String,String> lastAuthFinder,
                          java.util.function.Function<String,String> lastCookieFinder,
                          java.util.function.Function<String, java.util.List<String>> siteMapUrlsByHostFetcher,
                          java.util.function.Function<String, java.util.Map<String,String>> latestAuthCookieFinder) {
        this.store = store;
        this.settings = settings;
        this.rescanAction = rescanAction;
        this.saveAction = saveAction;
        this.jsluiceService = jsluiceService;
        this.repeaterSender = repeaterSender;
        this.lastAuthFinder = lastAuthFinder;
        this.lastCookieFinder = lastCookieFinder;
        this.siteMapUrlsByHostFetcher = siteMapUrlsByHostFetcher;
        this.latestAuthCookieFinder = latestAuthCookieFinder;

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Parameters", buildParametersPanel());
        tabs.addTab("Endpoints", buildEndpointsPanel());
        tabs.addTab("NotSure", buildNotSurePanel());
        tabs.addTab("Jsluice", buildJsluicePanel());
        tabs.addTab("Settings", buildSettingsPanel());
        root.add(tabs, BorderLayout.CENTER);

        // table models
        paramModel = new ParameterTableModel();
        paramTable.setModel(paramModel);
        paramSorter.setModel(paramModel);

        endpointModel = new EndpointTableModel();
        endpointTable.setModel(endpointModel);
        endpointSorter.setModel(endpointModel);

        notSureModel = new EndpointTableModel();
        notSureTable.setModel(notSureModel);
        notSureSorter.setModel(notSureModel);

        jsluiceModel = new JsluiceTableModel();
        jsluiceTable.setModel(jsluiceModel);
        jsluiceSorter.setModel(jsluiceModel);

        refreshAll();
    }

    public Component getComponent() { return root; }

    public void refreshAll() {
        SwingUtilities.invokeLater(() -> {
            paramModel.setRows(store.snapshotParameters());
            java.util.Set<String> ignored = new java.util.HashSet<>();
            for (String s : settings.getGlobalIgnoredValues()) if (s != null && !s.isBlank()) ignored.add(s.trim());
            java.util.List<EndpointRecord> eps = store.snapshotEndpoints();
            if (!ignored.isEmpty()) {
                eps = eps.stream().filter(e -> e == null || e.endpointString == null || !ignored.contains(e.endpointString.trim())).toList();
            }
            endpointModel.setRows(eps);

            java.util.List<EndpointRecord> ns = store.snapshotNotSureEndpoints();
            if (!ignored.isEmpty()) {
                ns = ns.stream().filter(e -> e == null || e.endpointString == null || !ignored.contains(e.endpointString.trim())).toList();
            }
            notSureModel.setRows(ns);
            if (jsluiceService != null) jsluiceModel.setRows(jsluiceService.snapshotResults());
        });
    }

    public void refreshSettingsFromModel() {
        SwingUtilities.invokeLater(() -> {
            scopeOnly.setSelected(settings.isScopeOnly());
            autoSaveSec.setValue(settings.getAutoSaveSeconds());
            maxInlineKb.setValue(settings.getMaxInlineJsKb());
            maxQueue.setValue(settings.getMaxQueueSize());
            exportDir.setText(settings.getExportDir().toString());
            ignoredModel.clear();
            for (String s : settings.getGlobalIgnoredSources()) ignoredModel.addElement(s);
            refreshVarDefaultsList();
            refreshDefaultHeadersList();
        });
    }

    // no longer needed: per-source filtering handled via record flags and DataStore snapshots

    // Attach live, case-insensitive substring filter that matches across all columns
    private static void attachTextFilter(JTextField field, TableRowSorter<? extends AbstractTableModel> sorter, int... columns) {
        DocumentListener dl = new DocumentListener() {
            private void update() {
                String text = field.getText();
                if (text == null || text.isBlank()) {
                    sorter.setRowFilter(null);
                    return;
                }
                final String needle = text.toLowerCase(Locale.ROOT);
                sorter.setRowFilter(new RowFilter<javax.swing.table.TableModel, Integer>() {
                    @Override
                    public boolean include(Entry<? extends javax.swing.table.TableModel, ? extends Integer> entry) {
                        int valueCount = entry.getValueCount();
                        if (columns != null && columns.length > 0) {
                            for (int c : columns) {
                                if (c >= 0 && c < valueCount) {
                                    Object v = entry.getValue(c);
                                    if (v != null && v.toString().toLowerCase(Locale.ROOT).contains(needle)) return true;
                                }
                            }
                            return false;
                        }
                        for (int i = 0; i < valueCount; i++) {
                            Object v = entry.getValue(i);
                            if (v != null && v.toString().toLowerCase(Locale.ROOT).contains(needle)) return true;
                        }
                        return false;
                    }
                });
            }
            @Override public void insertUpdate(DocumentEvent e) { update(); }
            @Override public void removeUpdate(DocumentEvent e) { update(); }
            @Override public void changedUpdate(DocumentEvent e) { update(); }
        };
        field.getDocument().addDocumentListener(dl);
        // Also trigger on Enter as a fallback
        field.addActionListener(e -> {
            // ensure we update even if Document events are missed
            String text = field.getText();
            if (text == null || text.isBlank()) sorter.setRowFilter(null);
            else {
                final String needle = text.toLowerCase(Locale.ROOT);
                sorter.setRowFilter(new RowFilter<javax.swing.table.TableModel, Integer>() {
                    @Override
                    public boolean include(Entry<? extends javax.swing.table.TableModel, ? extends Integer> entry) {
                        int valueCount = entry.getValueCount();
                        if (columns != null && columns.length > 0) {
                            for (int c : columns) {
                                if (c >= 0 && c < valueCount) {
                                    Object v = entry.getValue(c);
                                    if (v != null && v.toString().toLowerCase(Locale.ROOT).contains(needle)) return true;
                                }
                            }
                            return false;
                        }
                        for (int i = 0; i < valueCount; i++) {
                            Object v = entry.getValue(i);
                            if (v != null && v.toString().toLowerCase(Locale.ROOT).contains(needle)) return true;
                        }
                        return false;
                    }
                });
            }
        });
    }

    private JPanel buildParametersPanel() {
        JPanel p = new JPanel(new BorderLayout());
        JTextField filter = new JTextField();
        JButton copy = new JButton("Copy");
        JButton export = new JButton("Export selected");

        paramTable.setAutoCreateRowSorter(false);
        paramTable.setRowSorter(paramSorter);

        attachTextFilter(filter, paramSorter, 0);

        copy.addActionListener((ActionEvent e) -> {
            int[] rows = paramTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int r : rows) {
                int m = paramTable.convertRowIndexToModel(r);
                sb.append(paramModel.rows.get(m).name).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
        });

        // Right-click popup for copying first column and marking false positives
        JPopupMenu paramPopup = new JPopupMenu();
        JMenuItem paramCopyItem = new JMenuItem("Copy");
        paramCopyItem.addActionListener(e -> {
            int[] rows = paramTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int r : rows) {
                int m = paramTable.convertRowIndexToModel(r);
                sb.append(paramModel.rows.get(m).name).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
        });
        paramPopup.add(paramCopyItem);
        JMenuItem paramFalsePosItem = new JMenuItem("Mark as False Positive");
        paramFalsePosItem.addActionListener(e -> {
            int[] rows = paramTable.getSelectedRows();
            for (int r : rows) {
                int m = paramTable.convertRowIndexToModel(r);
                ParameterRecord rec = paramModel.rows.get(m);
                if (rec == null || rec.name == null || rec.name.isBlank()) continue;
                store.markParameterFalsePositive(rec.name, true);
            }
            refreshAll();
        });
        paramPopup.add(paramFalsePosItem);
        paramTable.setComponentPopupMenu(paramPopup);
        paramTable.addMouseListener(new MouseAdapter() {
            private void adjustSelection(MouseEvent e) {
                int row = paramTable.rowAtPoint(e.getPoint());
                if (row >= 0 && !paramTable.getSelectionModel().isSelectedIndex(row)) {
                    paramTable.setRowSelectionInterval(row, row);
                }
            }
            @Override public void mousePressed(MouseEvent e) { if (e.isPopupTrigger()) adjustSelection(e); }
            @Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) adjustSelection(e); }
        });

        export.addActionListener(e -> saveAction.run());

        JPanel top = new JPanel(new BorderLayout());
        top.add(new JLabel("Filter:"), BorderLayout.WEST);
        top.add(filter, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(copy);
        actions.add(export);
        top.add(actions, BorderLayout.EAST);

        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(paramTable), BorderLayout.CENTER);
        return p;
    }

    private JPanel buildEndpointsPanel() {
        JPanel p = new JPanel(new BorderLayout());
        JTextField filter = new JTextField();
        JButton copy = new JButton("Copy");
        JButton addManual = new JButton("Add manually");
        JButton sendToRepeater = new JButton("Send to Repeater");
        JButton openInProxy = new JButton("Open in Proxy History");

        endpointTable.setAutoCreateRowSorter(false);
        endpointTable.setRowSorter(endpointSorter);

        endpointContext.setEditable(false);
        endpointContext.setLineWrap(true);

        endpointTable.getSelectionModel().addListSelectionListener(e -> {
            int r = endpointTable.getSelectedRow();
            if (r >= 0) {
                int m = endpointTable.convertRowIndexToModel(r);
                endpointContext.setText(Optional.ofNullable(endpointModel.rows.get(m).contextSnippet).orElse(""));
            }
        });

        attachTextFilter(filter, endpointSorter, 0);

        copy.addActionListener((ActionEvent e) -> {
            int[] rows = endpointTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int r : rows) {
                int m = endpointTable.convertRowIndexToModel(r);
                sb.append(endpointModel.rows.get(m).endpointString).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
        });

        // Right-click popup for copying first column
        JPopupMenu endpointPopup = new JPopupMenu();
        JMenuItem endpointCopyItem = new JMenuItem("Copy");
        endpointCopyItem.addActionListener(e -> {
            int[] rows = endpointTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int r : rows) {
                int m = endpointTable.convertRowIndexToModel(r);
                sb.append(endpointModel.rows.get(m).endpointString).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
        });
        endpointPopup.add(endpointCopyItem);
        JMenuItem endpointSendRepeater = new JMenuItem("Send to Repeater");
        endpointSendRepeater.addActionListener(e -> {
            int r = endpointTable.getSelectedRow();
            if (r >= 0) {
                int m = endpointTable.convertRowIndexToModel(r);
                EndpointRecord rec = endpointModel.rows.get(m);
                openSendDialogForEndpoint(rec);
            }
        });
        endpointPopup.add(endpointSendRepeater);
        JMenuItem endpointRunHttpx = new JMenuItem("Run httpx (spray endpoints)");
        endpointRunHttpx.addActionListener(e -> runHttpxForEndpointSelection());
        endpointPopup.add(endpointRunHttpx);
        JMenuItem endpointFalsePosItem = new JMenuItem("Mark as False Positive");
        endpointFalsePosItem.addActionListener(e -> {
            int[] rows = endpointTable.getSelectedRows();
            for (int r : rows) {
                int m = endpointTable.convertRowIndexToModel(r);
                EndpointRecord rec = endpointModel.rows.get(m);
                if (rec == null || rec.endpointString == null || rec.endpointString.isBlank()) continue;
                store.markEndpointFalsePositive(rec.endpointString, rec.source, true);
            }
            refreshAll();
        });
        endpointPopup.add(endpointFalsePosItem);
        JMenuItem endpointAddToGlobalIgnored = new JMenuItem("Add Endpoint to Global Ignored");
        endpointAddToGlobalIgnored.addActionListener(e -> {
            int[] rows = endpointTable.getSelectedRows();
            boolean changed = false;
            for (int r : rows) {
                int m = endpointTable.convertRowIndexToModel(r);
                EndpointRecord rec = endpointModel.rows.get(m);
                if (rec == null) continue;
                String val = rec.endpointString;
                if (val != null && !val.isBlank()) {
                    settings.addGlobalIgnoredValue(val.trim());
                    pruneEndpointEverywhere(val.trim());
                    changed = true;
                }
            }
            if (changed) {
                settings.saveGlobalIgnoredValuesToGlobalDir();
                refreshAll();
            }
        });
        endpointPopup.add(endpointAddToGlobalIgnored);
        endpointTable.setComponentPopupMenu(endpointPopup);
        endpointTable.addMouseListener(new MouseAdapter() {
            private void adjustSelection(MouseEvent e) {
                int row = endpointTable.rowAtPoint(e.getPoint());
                if (row >= 0 && !endpointTable.getSelectionModel().isSelectedIndex(row)) {
                    endpointTable.setRowSelectionInterval(row, row);
                }
            }
            @Override public void mousePressed(MouseEvent e) { if (e.isPopupTrigger()) adjustSelection(e); }
            @Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) adjustSelection(e); }
        });

        sendToRepeater.addActionListener(e -> {
            int r = endpointTable.getSelectedRow();
            if (r >= 0) {
                int m = endpointTable.convertRowIndexToModel(r);
                EndpointRecord rec = endpointModel.rows.get(m);
                openSendDialogForEndpoint(rec);
            }
        });

        addManual.addActionListener(e -> {
            Window owner = SwingUtilities.getWindowAncestor(root);
            AddManualEndpointsDialog dlg = new AddManualEndpointsDialog(owner, (data) -> {
                try {
                    java.util.List<String> eps = data.endpoints();
                    if (eps == null || eps.isEmpty()) return;
                    String source = data.sourceJs() == null ? "" : data.sourceJs().trim();
                    String ref = data.referer() == null ? "" : data.referer().trim();
                    for (String ep : eps) {
                        if (ep == null) continue;
                        String val = ep.trim();
                        if (val.isEmpty()) continue;
                        store.addOrUpdateEndpoint(val, EndpointRecord.Type.MANUALLY, true, source, null, null, false, ref);
                    }
                    // Persist and refresh UI
                    try { saveAction.run(); } catch (Throwable ignored) {}
                    refreshAll();
                } catch (Throwable ex) {
                    JOptionPane.showMessageDialog(root, "Failed to add endpoints: " + ex.getMessage(), "Paramamador", JOptionPane.ERROR_MESSAGE);
                }
            });
            dlg.setVisible(true);
        });

        JPanel top = new JPanel(new BorderLayout());
        top.add(new JLabel("Filter:"), BorderLayout.WEST);
        top.add(filter, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(copy);
        actions.add(addManual);
        actions.add(sendToRepeater);
        actions.add(openInProxy);
        top.add(actions, BorderLayout.EAST);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(endpointTable), new JScrollPane(endpointContext));
        split.setResizeWeight(0.8);

        p.add(top, BorderLayout.NORTH);
        p.add(split, BorderLayout.CENTER);
        return p;
    }

    private JPanel buildNotSurePanel() {
        JPanel p = new JPanel(new BorderLayout());
        JTextField filter = new JTextField();
        JButton copy = new JButton("Copy");

        notSureTable.setAutoCreateRowSorter(false);
        notSureTable.setRowSorter(notSureSorter);

        notSureContext.setEditable(false);
        notSureContext.setLineWrap(true);

        notSureTable.getSelectionModel().addListSelectionListener(e -> {
            int r = notSureTable.getSelectedRow();
            if (r >= 0) {
                int m = notSureTable.convertRowIndexToModel(r);
                notSureContext.setText(Optional.ofNullable(notSureModel.rows.get(m).contextSnippet).orElse(""));
            }
        });

        attachTextFilter(filter, notSureSorter, 0);

        copy.addActionListener((ActionEvent e) -> {
            int[] rows = notSureTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int r : rows) {
                int m = notSureTable.convertRowIndexToModel(r);
                sb.append(notSureModel.rows.get(m).endpointString).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
        });

        // Right-click popup for copying first column
        JPopupMenu notSurePopup = new JPopupMenu();
        JMenuItem notSureCopyItem = new JMenuItem("Copy");
        notSureCopyItem.addActionListener(e -> {
            int[] rows = notSureTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int r : rows) {
                int m = notSureTable.convertRowIndexToModel(r);
                sb.append(notSureModel.rows.get(m).endpointString).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
        });
        notSurePopup.add(notSureCopyItem);
        JMenuItem notSureFalsePosItem = new JMenuItem("Mark as False Positive");
        notSureFalsePosItem.addActionListener(e -> {
            int[] rows = notSureTable.getSelectedRows();
            for (int r : rows) {
                int m = notSureTable.convertRowIndexToModel(r);
                EndpointRecord rec = notSureModel.rows.get(m);
                if (rec == null || rec.endpointString == null || rec.endpointString.isBlank()) continue;
                store.markEndpointFalsePositive(rec.endpointString, rec.source, true);
            }
            refreshAll();
        });
        notSurePopup.add(notSureFalsePosItem);
        JMenuItem notSureAddToGlobalIgnored = new JMenuItem("Add Endpoint to Global Ignored");
        notSureAddToGlobalIgnored.addActionListener(e -> {
            int[] rows = notSureTable.getSelectedRows();
            boolean changed = false;
            for (int r : rows) {
                int m = notSureTable.convertRowIndexToModel(r);
                EndpointRecord rec = notSureModel.rows.get(m);
                if (rec == null) continue;
                String val = rec.endpointString;
                if (val != null && !val.isBlank()) {
                    settings.addGlobalIgnoredValue(val.trim());
                    pruneEndpointEverywhere(val.trim());
                    changed = true;
                }
            }
            if (changed) {
                settings.saveGlobalIgnoredValuesToGlobalDir();
                refreshAll();
            }
        });
        JMenuItem notSureSend = new JMenuItem("Send to Repeater");
        notSureSend.addActionListener(e -> {
            int r = notSureTable.getSelectedRow();
            if (r >= 0) {
                int m = notSureTable.convertRowIndexToModel(r);
                EndpointRecord rec = notSureModel.rows.get(m);
                openSendDialogForEndpoint(rec);
            }
        });
        notSurePopup.add(notSureSend);
        notSurePopup.add(notSureAddToGlobalIgnored);
        notSureTable.setComponentPopupMenu(notSurePopup);
        notSureTable.addMouseListener(new MouseAdapter() {
            private void adjustSelection(MouseEvent e) {
                int row = notSureTable.rowAtPoint(e.getPoint());
                if (row >= 0 && !notSureTable.getSelectionModel().isSelectedIndex(row)) {
                    notSureTable.setRowSelectionInterval(row, row);
                }
            }
            @Override public void mousePressed(MouseEvent e) { if (e.isPopupTrigger()) adjustSelection(e); }
            @Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) adjustSelection(e); }
        });

        JPanel top = new JPanel(new BorderLayout());
        top.add(new JLabel("Filter:"), BorderLayout.WEST);
        top.add(filter, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(copy);
        top.add(actions, BorderLayout.EAST);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(notSureTable), new JScrollPane(notSureContext));
        split.setResizeWeight(0.8);

        p.add(top, BorderLayout.NORTH);
        p.add(split, BorderLayout.CENTER);
        return p;
    }

    private JPanel buildJsluicePanel() {
        JPanel p = new JPanel(new BorderLayout());
        JTextField filter = new JTextField();
        JButton copy = new JButton("Copy URLs");

        jsluiceTable.setAutoCreateRowSorter(false);
        jsluiceTable.setRowSorter(jsluiceSorter);

        attachTextFilter(filter, jsluiceSorter, 0);

        copy.addActionListener((ActionEvent e) -> {
            int[] rows = jsluiceTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int r : rows) {
                int m = jsluiceTable.convertRowIndexToModel(r);
                sb.append(jsluiceModel.rows.get(m).url == null ? "" : jsluiceModel.rows.get(m).url).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
        });

        JPanel top = new JPanel(new BorderLayout());
        top.add(new JLabel("Filter:"), BorderLayout.WEST);
        top.add(filter, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(copy);
        top.add(actions, BorderLayout.EAST);

        // Right-click popup for jsluice table (Copy URL, Send to Repeater)
        JPopupMenu jsluicePopup = new JPopupMenu();
        JMenuItem jCopyItem = new JMenuItem("Copy URL");
        jCopyItem.addActionListener(e -> {
            int[] rows = jsluiceTable.getSelectedRows();
            StringBuilder sb1 = new StringBuilder();
            for (int r : rows) {
                int m = jsluiceTable.convertRowIndexToModel(r);
                String u = jsluiceModel.rows.get(m).url;
                sb1.append(u == null ? "" : u).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb1.toString()), null);
        });
        JMenuItem jSendItem = new JMenuItem("Send to Repeater");
        jSendItem.addActionListener(e -> {
            int r = jsluiceTable.getSelectedRow();
            if (r >= 0) {
                int m = jsluiceTable.convertRowIndexToModel(r);
                JsluiceUrlRecord rec = jsluiceModel.rows.get(m);
                openSendDialogForJsluice(rec);
            }
        });
        jsluicePopup.add(jCopyItem);
        jsluicePopup.add(jSendItem);
        JMenuItem jHttpxItem = new JMenuItem("Run httpx (spray endpoints)");
        jHttpxItem.addActionListener(e -> runHttpxForJsluiceSelection());
        jsluicePopup.add(jHttpxItem);
        jsluiceTable.setComponentPopupMenu(jsluicePopup);
        jsluiceTable.addMouseListener(new MouseAdapter() {
            private void adjustSelection(MouseEvent e) {
                int row = jsluiceTable.rowAtPoint(e.getPoint());
                if (row >= 0 && !jsluiceTable.getSelectionModel().isSelectedIndex(row)) {
                    jsluiceTable.setRowSelectionInterval(row, row);
                }
            }
            @Override public void mousePressed(MouseEvent e) { if (e.isPopupTrigger()) adjustSelection(e); }
            @Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) adjustSelection(e); }
        });

        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(jsluiceTable), BorderLayout.CENTER);
        return p;
    }

    private JPanel buildSettingsPanel() {
        JPanel p = new JPanel(new BorderLayout());

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4,4,4,4);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;

        int row = 0;
        c.gridx = 0; c.gridy = row; form.add(new JLabel("Scope only"), c);
        c.gridx = 1; scopeOnly.setSelected(settings.isScopeOnly()); form.add(scopeOnly, c); row++;

        c.gridx = 0; c.gridy = row; form.add(new JLabel("Auto-save interval (sec)"), c);
        c.gridx = 1; autoSaveSec.setValue(settings.getAutoSaveSeconds()); form.add(autoSaveSec, c); row++;

        c.gridx = 0; c.gridy = row; form.add(new JLabel("Max inline JS size (KB)"), c);
        c.gridx = 1; maxInlineKb.setValue(settings.getMaxInlineJsKb()); form.add(maxInlineKb, c); row++;

        c.gridx = 0; c.gridy = row; form.add(new JLabel("Max queue size"), c);
        c.gridx = 1; maxQueue.setValue(settings.getMaxQueueSize()); form.add(maxQueue, c); row++;

        c.gridx = 0; c.gridy = row; form.add(new JLabel("Export folder"), c);
        c.gridx = 1; exportDir.setText(settings.getExportDir().toString()); form.add(exportDir, c); row++;

        c.gridx = 0; c.gridy = row; form.add(new JLabel("Ignored patterns"), c);
        settings.getGlobalIgnoredSources().forEach(ignoredModel::addElement);
        JList<String> ignored = new JList<>(ignoredModel);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField newPattern = new JTextField(20);
        JButton add = new JButton("Add");
        JButton remove = new JButton("Remove selected");
        add.addActionListener(e -> {
            if (!newPattern.getText().isBlank()) {
                settings.addGlobalIgnoredSource(newPattern.getText().trim());
                ignoredModel.addElement(newPattern.getText().trim());
                settings.saveGlobalIgnoredSourcesToGlobalDir();
                newPattern.setText("");
            }
        });
        remove.addActionListener(e -> {
            for (String s : ignored.getSelectedValuesList()) {
                settings.removeGlobalIgnoredSource(s);
                ignoredModel.removeElement(s);
            }
            settings.saveGlobalIgnoredSourcesToGlobalDir();
        });
        buttons.add(new JLabel("Global source substring:"));
        buttons.add(newPattern);
        buttons.add(add);
        buttons.add(remove);
        c.gridx = 1; c.gridy = row; form.add(new JScrollPane(ignored), c); row++;
        c.gridx = 1; c.gridy = row; form.add(buttons, c); row++;

        // Path variable defaults (e.g., :client -> acme)
        c.gridx = 0; c.gridy = row; form.add(new JLabel("Path variable defaults"), c);
        JList<String> varDefaults = new JList<>(varDefaultsModel);
        JPanel varBtns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField varName = new JTextField(12);
        JTextField varValue = new JTextField(12);
        JButton varAdd = new JButton("Add/Update");
        JButton varRemove = new JButton("Remove selected");
        varAdd.addActionListener(e -> {
            String n = varName.getText() == null ? "" : varName.getText().trim();
            String v = varValue.getText() == null ? "" : varValue.getText().trim();
            if (!n.isEmpty()) {
                settings.addVariableDefault(n, v);
                settings.saveVariableDefaultsToFile();
                refreshVarDefaultsList();
                varName.setText(""); varValue.setText("");
            }
        });
        varRemove.addActionListener(e -> {
            for (String s : varDefaults.getSelectedValuesList()) {
                int eq = s.indexOf('=');
                String key = eq >= 0 ? s.substring(0, eq) : s;
                settings.removeVariableDefault(key);
            }
            settings.saveVariableDefaultsToFile();
            refreshVarDefaultsList();
        });
        varBtns.add(new JLabel("Name (:name)"));
        varBtns.add(varName);
        varBtns.add(new JLabel("Value"));
        varBtns.add(varValue);
        varBtns.add(varAdd);
        varBtns.add(varRemove);
        c.gridx = 1; c.gridy = row; form.add(new JScrollPane(varDefaults), c); row++;
        c.gridx = 1; c.gridy = row; form.add(varBtns, c); row++;

        // Default request headers (name:value) added to Send-to-Repeater
        c.gridx = 0; c.gridy = row; form.add(new JLabel("Default request headers"), c);
        JList<String> defHeaders = new JList<>(defaultHeadersModel);
        JPanel dhBtns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField dhName = new JTextField(12);
        JTextField dhValue = new JTextField(16);
        JButton dhAdd = new JButton("Add/Update");
        JButton dhRemove = new JButton("Remove selected");
        dhAdd.addActionListener(e -> {
            String n = dhName.getText() == null ? "" : dhName.getText().trim();
            String v = dhValue.getText() == null ? "" : dhValue.getText().trim();
            if (!n.isEmpty()) {
                settings.addDefaultHeader(n, v);
                settings.saveDefaultHeadersToFile();
                refreshDefaultHeadersList();
                dhName.setText(""); dhValue.setText("");
            }
        });
        dhRemove.addActionListener(e -> {
            for (String s : defHeaders.getSelectedValuesList()) {
                int idx = s.indexOf(':');
                String key = idx >= 0 ? s.substring(0, idx).trim() : s.trim();
                settings.removeDefaultHeader(key);
            }
            settings.saveDefaultHeadersToFile();
            refreshDefaultHeadersList();
        });
        dhBtns.add(new JLabel("Header"));
        dhBtns.add(dhName);
        dhBtns.add(new JLabel("Value"));
        dhBtns.add(dhValue);
        dhBtns.add(dhAdd);
        dhBtns.add(dhRemove);
        c.gridx = 1; c.gridy = row; form.add(new JScrollPane(defHeaders), c); row++;
        c.gridx = 1; c.gridy = row; form.add(dhBtns, c); row++;

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton apply = new JButton("Apply");
        JButton clear = new JButton("Clear data");
        JButton rescan = new JButton("Rescan Site Tree");
        JButton save = new JButton("Save now");
        JButton load = new JButton("Load JSON...");

        apply.addActionListener(e -> applySettings());
        clear.addActionListener(e -> clearData());
        rescan.addActionListener(e -> rescanAction.run());
        save.addActionListener(e -> saveAction.run());
        load.addActionListener(e -> {
            try {
                JFileChooser fc = new JFileChooser();
                fc.setDialogTitle("Load Paramamador JSON");
                fc.setMultiSelectionEnabled(true);
                fc.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
                try {
                    fc.setCurrentDirectory(settings.getExportDir().toFile());
                } catch (Throwable t1) {}
                int result = fc.showOpenDialog(root);
                if (result == JFileChooser.APPROVE_OPTION) {
                    java.io.File[] selected = fc.getSelectedFiles();
                    if (selected != null && selected.length > 0) {
                        List<Path> paths = new ArrayList<>();
                        for (java.io.File f : selected) paths.add(f.toPath());
                        store.loadFromFiles(paths);
                        refreshAll();
                        JOptionPane.showMessageDialog(root, "Loaded " + selected.length + " file(s).", "Paramamador", JOptionPane.INFORMATION_MESSAGE);
                    }
                }
            } catch (Throwable ex) {
                JOptionPane.showMessageDialog(root, "Load failed: " + ex.getMessage(), "Paramamador", JOptionPane.ERROR_MESSAGE);
            }
        });

        actions.add(apply); actions.add(clear); actions.add(rescan); actions.add(save); actions.add(load);

        p.add(form, BorderLayout.CENTER);
        p.add(actions, BorderLayout.SOUTH);
        return p;
    }

    private void openSendDialogForEndpoint(EndpointRecord rec) {
        if (rec == null) return;
        String ep = rec.endpointString == null ? "" : rec.endpointString.trim();
        String path = applyVarDefaults(extractPath(ep));
        String refererUrl = rec.referer == null ? "" : rec.referer;
        String jsUrl = rec.source == null ? "" : rec.source;
        SendToRepeaterDialog dlg = new SendToRepeaterDialog(SwingUtilities.getWindowAncestor(root), path, refererUrl, jsUrl, settings.getDefaultHeaders(), repeaterSender, lastAuthFinder, lastCookieFinder);
        dlg.setVisible(true);
    }

    private void openSendDialogForJsluice(JsluiceUrlRecord rec) {
        if (rec == null) return;
        String url = rec.url == null ? "" : rec.url.trim();
        String path = applyVarDefaults(extractPath(url));
        String refererUrl = rec.refererUrl;
        String jsUrl = rec.sourceJsUrl;
        SendToRepeaterDialog dlg = new SendToRepeaterDialog(SwingUtilities.getWindowAncestor(root), path, refererUrl, jsUrl, settings.getDefaultHeaders(), repeaterSender, lastAuthFinder, lastCookieFinder);
        dlg.setVisible(true);
    }

    // ---- httpx integration popups ----
    private void runHttpxForEndpointSelection() {
        try {
            int[] rows = endpointTable.getSelectedRows();
            if (rows == null || rows.length == 0) {
                JOptionPane.showMessageDialog(root, "No endpoints selected.", "Paramamador", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            java.util.Set<String> endpoints = new java.util.LinkedHashSet<>();
            java.util.LinkedHashSet<String> hosts = new java.util.LinkedHashSet<>();
            for (int r : rows) {
                int m = endpointTable.convertRowIndexToModel(r);
                EndpointRecord rec = endpointModel.rows.get(m);
                if (rec == null) continue;
                if (rec.endpointString != null && !rec.endpointString.isBlank()) endpoints.add(rec.endpointString.trim());
                String ref = rec.referer == null ? "" : rec.referer.trim();
                String host = extractHostPort(ref);
                if (host != null && !host.isBlank()) hosts.add(host);
            }
            if (endpoints.isEmpty() || hosts.isEmpty()) {
                JOptionPane.showMessageDialog(root, "Need endpoints and referer host.", "Paramamador", JOptionPane.WARNING_MESSAGE);
                return;
            }
            runHttpxWithInputs(endpoints, hosts);
        } catch (Throwable t) {
            JOptionPane.showMessageDialog(root, "httpx prep failed: " + t.getMessage(), "Paramamador", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void runHttpxForJsluiceSelection() {
        try {
            int[] rows = jsluiceTable.getSelectedRows();
            if (rows == null || rows.length == 0) {
                JOptionPane.showMessageDialog(root, "No URLs selected.", "Paramamador", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            java.util.Set<String> endpoints = new java.util.LinkedHashSet<>();
            java.util.LinkedHashSet<String> hosts = new java.util.LinkedHashSet<>();
            for (int r : rows) {
                int m = jsluiceTable.convertRowIndexToModel(r);
                JsluiceUrlRecord rec = jsluiceModel.rows.get(m);
                if (rec == null) continue;
                if (rec.url != null && !rec.url.isBlank()) endpoints.add(rec.url.trim());
                String ref = rec.refererUrl == null ? "" : rec.refererUrl.trim();
                String host = extractHostPort(ref);
                if (host != null && !host.isBlank()) hosts.add(host);
            }
            if (endpoints.isEmpty() || hosts.isEmpty()) {
                JOptionPane.showMessageDialog(root, "Need URLs and referer host.", "Paramamador", JOptionPane.WARNING_MESSAGE);
                return;
            }
            runHttpxWithInputs(endpoints, hosts);
        } catch (Throwable t) {
            JOptionPane.showMessageDialog(root, "httpx prep failed: " + t.getMessage(), "Paramamador", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void runHttpxWithInputs(java.util.Set<String> endpoints, java.util.LinkedHashSet<String> hosts) throws Exception {
        // 1) Collect SiteMap URLs for each host and explode into base candidates
        java.util.Set<String> baseCandidates = new java.util.LinkedHashSet<>();
        for (String host : hosts) {
            java.util.List<String> urls = siteMapUrlsByHostFetcher == null ? java.util.List.of() : siteMapUrlsByHostFetcher.apply(host);
            if (urls == null) continue;
            for (String u : urls) {
                if (u == null || u.isBlank()) continue;
                for (String b : explodeUrlBases(u)) baseCandidates.add(b);
            }
        }
        if (baseCandidates.isEmpty()) {
            JOptionPane.showMessageDialog(root, "No Site Map URLs found for the host(s).", "Paramamador", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 2) Concat endpoints with base candidates and normalize
        java.util.Set<String> finalUrls = new java.util.LinkedHashSet<>();
        for (String e : endpoints) {
            if (e == null || e.isBlank()) continue;
            String original = e.trim();
            boolean abs = isAbsoluteUrl(original);
            String pathWithQuery = applyVarDefaults(extractPath(original));
            if (abs) {
                String rebuilt = rebuildAbsoluteWithPath(original, pathWithQuery);
                finalUrls.add(normalizeUrl(rebuilt));
            } else {
                for (String b : baseCandidates) {
                    finalUrls.add(normalizeUrl(concatUrl(b, pathWithQuery)));
                }
            }
        }
        if (finalUrls.isEmpty()) {
            JOptionPane.showMessageDialog(root, "No URLs to write.", "Paramamador", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 3) Save to temp file with random name
        java.nio.file.Path tmpDir = java.nio.file.Path.of("/tmp");
        if (!java.nio.file.Files.isDirectory(tmpDir)) tmpDir = java.nio.file.Path.of(System.getProperty("java.io.tmpdir"));
        String baseName = "paramamador_httpx_" + java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 8) + ".json";
        java.nio.file.Path inputFile = tmpDir.resolve(baseName);
        java.nio.file.Files.createDirectories(inputFile.getParent());
        java.nio.file.Files.write(inputFile, finalUrls, java.nio.charset.StandardCharsets.UTF_8);

        // 4) Prepare output path under exportDir/httpx with same base name
        java.nio.file.Path outDir = settings.getExportDir().resolve("httpx");
        try { java.nio.file.Files.createDirectories(outDir); } catch (Throwable ignored) {}
        java.nio.file.Path outFile = outDir.resolve(baseName);

        // 5) Gather headers from proxy history for the first host with data
        String chosenHost = hosts.iterator().next();
        java.util.Map<String,String> hdrs = latestAuthCookieFinder == null ? java.util.Map.of() : latestAuthCookieFinder.apply(chosenHost);
        String cookieVal = hdrs == null ? null : hdrs.getOrDefault("Cookie", null);
        String authVal = hdrs == null ? null : hdrs.getOrDefault("Authorization", null);

        // 6) Build command
        StringBuilder cmd = new StringBuilder();
        cmd.append("httpx -l ")
           .append(quotePath(inputFile))
           .append(" -sc -ct -title -wc -fc 404 -v -t 3 -j -o ")
           .append(quotePath(outFile))
           .append(" -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\"");
        if (cookieVal != null && !cookieVal.isBlank()) cmd.append(" -H ").append(quoteHeader("Cookie", cookieVal));
        if (authVal != null && !authVal.isBlank()) cmd.append(" -H ").append(quoteHeader("Authorization", authVal));

        showHttpxCommandDialog(cmd.toString(), inputFile, outFile, finalUrls.size());
    }

    private static boolean isAbsoluteUrl(String s) {
        String l = s.toLowerCase(java.util.Locale.ROOT);
        return l.startsWith("http://") || l.startsWith("https://");
    }

    private static String concatUrl(String base, String endpoint) {
        String b = base;
        String e = endpoint;
        if (b.endsWith("/")) b = b.substring(0, b.length()-1);
        if (!e.startsWith("/")) e = "/" + e;
        return b + e;
    }

    private static String normalizeUrl(String url) {
        try {
            // Split scheme://authority and path?query
            String s = url;
            int schemeIdx = s.indexOf("://");
            if (schemeIdx < 0) return s;
            String scheme = s.substring(0, schemeIdx);
            String rest = s.substring(schemeIdx + 3);
            int slash = rest.indexOf('/');
            String authority = slash >= 0 ? rest.substring(0, slash) : rest;
            String pathQuery = slash >= 0 ? rest.substring(slash) : "/";
            String path;
            String query = null;
            int qpos = pathQuery.indexOf('?');
            if (qpos >= 0) { path = pathQuery.substring(0, qpos); query = pathQuery.substring(qpos + 1); }
            else { path = pathQuery; }
            // collapse duplicate slashes in path
            path = path.replaceAll("(?<!:)/{2,}", "/");
            // normalize segments
            java.util.Deque<String> stack = new java.util.ArrayDeque<>();
            for (String seg : path.split("/")) {
                if (seg.isEmpty() || seg.equals(".")) continue;
                if (seg.equals("..")) { if (!stack.isEmpty()) stack.removeLast(); }
                else stack.addLast(seg);
            }
            StringBuilder normPath = new StringBuilder("/");
            java.util.Iterator<String> it = stack.iterator();
            while (it.hasNext()) {
                normPath.append(it.next());
                if (it.hasNext()) normPath.append('/');
            }
            String out = scheme + "://" + authority + normPath.toString();
            if (query != null && !query.isBlank()) out += "?" + query;
            return out;
        } catch (Throwable ignored) {
            return url;
        }
    }

    private static String rebuildAbsoluteWithPath(String url, String newPathWithQuery) {
        try {
            if (url == null || url.isBlank()) return url;
            String s = url;
            int schemeIdx = s.indexOf("://");
            if (schemeIdx < 0) return url;
            String scheme = s.substring(0, schemeIdx);
            String rest = s.substring(schemeIdx + 3);
            int slash = rest.indexOf('/');
            String authority = slash >= 0 ? rest.substring(0, slash) : rest;
            String p = newPathWithQuery == null || newPathWithQuery.isBlank() ? "/" : newPathWithQuery.trim();
            if (!p.startsWith("/")) p = "/" + p;
            return scheme + "://" + authority + p;
        } catch (Throwable ignored) { return url; }
    }

    private static java.util.List<String> explodeUrlBases(String url) {
        java.util.List<String> out = new java.util.ArrayList<>();
        try {
            java.net.URI u = java.net.URI.create(url);
            String scheme = u.getScheme();
            String host = u.getHost();
            int port = u.getPort();
            if (scheme == null || host == null) return out;
            String base = scheme + "://" + host + (port > 0 ? ":" + port : "");
            String path = u.getRawPath();
            if (path == null || path.isBlank() || path.equals("/")) {
                out.add(base);
                return out;
            }
            // Split path and build decreasing variants
            String[] segs = path.split("/");
            java.util.List<String> nonEmpty = new java.util.ArrayList<>();
            for (String s : segs) if (!s.isEmpty()) nonEmpty.add(s);
            // Drop any segment that contains the literal "u0022" (noise from encoded quotes in JS)
            java.util.List<String> cleaned = new java.util.ArrayList<>();
            for (String seg : nonEmpty) {
                String lseg = seg.toLowerCase(java.util.Locale.ROOT);
                if (lseg.contains("u0022")) continue; // skip such segment entirely
                cleaned.add(seg);
            }
            nonEmpty = cleaned;
            // If last segment looks like a static asset (.js, .gif, .jpg, .png, .ico, .css, .woff, .woff2, .ttf, .svg),
            // drop it before generating bases
            int end = nonEmpty.size();
            if (end > 0) {
                String last = nonEmpty.get(end - 1).toLowerCase(java.util.Locale.ROOT);
                if (last.endsWith(".js") || last.endsWith(".gif") || last.endsWith(".jpg") || last.endsWith(".png")
                        || last.endsWith(".ico") || last.endsWith(".css") || last.endsWith(".woff") || last.endsWith(".woff2")
                        || last.endsWith(".ttf") || last.endsWith(".svg")) {
                    end = end - 1;
                }
            }
            // from (possibly trimmed) full path to root
            for (int i = end; i >= 1; i--) {
                String p = "/" + String.join("/", nonEmpty.subList(0, i));
                out.add(base + p);
            }
            out.add(base);
        } catch (Throwable ignored) {}
        return out;
    }

    private static String extractHostPort(String url) {
        try {
            if (url == null || url.isBlank()) return null;
            java.net.URI u = java.net.URI.create(url);
            String h = u.getHost();
            if (h == null || h.isBlank()) return null;
            int p = u.getPort();
            return p > 0 ? h + ":" + p : h;
        } catch (Throwable ignored) { return null; }
    }

    private static String quotePath(java.nio.file.Path p) {
        return "\"" + p.toString().replace("\"", "\\\"") + "\"";
    }

    private static String quoteHeader(String name, String value) {
        String v = value == null ? "" : value;
        // collapse CRLF just in case
        v = v.replace('\r', ' ').replace('\n', ' ');
        return "\"" + name + ": " + v.replace("\"", "\\\"") + "\"";
    }

    private void showHttpxCommandDialog(String cmd, java.nio.file.Path inputFile, java.nio.file.Path outFile, int count) {
        JDialog dlg = new JDialog(SwingUtilities.getWindowAncestor(root), "Paramamador: httpx command", Dialog.ModalityType.APPLICATION_MODAL);
        dlg.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dlg.setLayout(new BorderLayout(8,8));
        String info = "Input (" + count + ") -> " + inputFile + "\nOutput -> " + outFile + "\n\n" + cmd;
        JTextArea ta = new JTextArea(info);
        ta.setLineWrap(false);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane sp = new JScrollPane(ta);
        JButton copy = new JButton("Copy");
        copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(cmd), null));
        JButton ok = new JButton("OK");
        ok.addActionListener(e -> dlg.dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(copy); buttons.add(ok);
        dlg.add(sp, BorderLayout.CENTER);
        dlg.add(buttons, BorderLayout.SOUTH);
        dlg.setSize(900, 500);
        dlg.setLocationRelativeTo(SwingUtilities.getWindowAncestor(root));
        dlg.setVisible(true);
    }

    private static String extractPath(String maybeUrlOrPath) {
        if (maybeUrlOrPath == null || maybeUrlOrPath.isBlank()) return "/";
        String s = maybeUrlOrPath.trim();
        try {
            if (s.toLowerCase(java.util.Locale.ROOT).startsWith("http://") || s.toLowerCase(java.util.Locale.ROOT).startsWith("https://")) {
                java.net.URI u = java.net.URI.create(s);
                String p = u.getRawPath();
                if (p == null || p.isBlank()) p = "/";
                String q = u.getRawQuery();
                if (q != null && !q.isBlank()) return p + "?" + q;
                return p;
            }
        } catch (Throwable ignored) {}
        // treat as path
        if (!s.startsWith("/")) s = "/" + s;
        return s;
    }

    private void refreshVarDefaultsList() {
        varDefaultsModel.clear();
        java.util.Map<String,String> m = settings.getVariableDefaults();
        for (java.util.Map.Entry<String,String> e : m.entrySet()) varDefaultsModel.addElement(e.getKey() + "=" + (e.getValue()==null?"":e.getValue()));
    }

    private void refreshDefaultHeadersList() {
        defaultHeadersModel.clear();
        java.util.Map<String,String> m = settings.getDefaultHeaders();
        for (java.util.Map.Entry<String,String> e : m.entrySet()) defaultHeadersModel.addElement(e.getKey() + ": " + (e.getValue()==null?"":e.getValue()));
    }

    private String applyVarDefaults(String path) {
        if (path == null || path.isBlank()) return path;
        String p = path;
        java.util.Map<String,String> defs = settings.getVariableDefaults();
        if (defs.isEmpty()) return p;
        String[] parts = p.split("\\?", 2);
        String head = parts[0];
        for (java.util.Map.Entry<String,String> e : defs.entrySet()) {
            String name = e.getKey();
            String val = e.getValue();
            if (name == null || name.isBlank()) continue;
            head = head.replace(":" + name, val == null ? "" : val);
        }
        if (parts.length > 1) return head + "?" + parts[1];
        return head;
    }

    private void pruneEndpointEverywhere(String endpointValue) {
        if (endpointValue == null || endpointValue.isBlank()) return;
        String needle = endpointValue.trim();
        try {
            java.util.Iterator<java.util.Map.Entry<String, EndpointRecord>> it = store.endpoints().entrySet().iterator();
            while (it.hasNext()) {
                java.util.Map.Entry<String, EndpointRecord> en = it.next();
                EndpointRecord rec = en.getValue();
                if (rec != null && rec.endpointString != null && needle.equals(rec.endpointString.trim())) {
                    it.remove();
                }
            }
        } catch (Throwable ignored) {}
    }

    private void applySettings() {
        settings.setScopeOnly(scopeOnly.isSelected());
        settings.setAutoSaveSeconds((Integer) autoSaveSec.getValue());
        settings.setMaxInlineJsKb((Integer) maxInlineKb.getValue());
        settings.setMaxQueueSize((Integer) maxQueue.getValue());
        settings.setExportDir(Path.of(exportDir.getText()));
        // Reload ignore lists from the (possibly) new global export directory
        settings.loadGlobalIgnoredSourcesFromGlobalDir();
        settings.loadGlobalIgnoredValuesFromGlobalDir();
        // Refresh the Ignored Patterns list UI
        ignoredModel.clear();
        for (String s : settings.getGlobalIgnoredSources()) ignoredModel.addElement(s);
        try { settings.saveToYaml(); } catch (Throwable ignored) {}
    }

    private void clearData() {
        store.clearAll();
        refreshAll();
    }

    // Table models
    private static class ParameterTableModel extends AbstractTableModel {
        private final String[] cols = {"Name", "Sources", "Types", "Examples", "Count", "OnlyInCode", "Pattern"};
        private List<ParameterRecord> rows = new ArrayList<>();

        public void setRows(List<ParameterRecord> r) { this.rows = new ArrayList<>(r); fireTableDataChanged(); }
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int column) { return cols[column]; }
        @Override public Object getValueAt(int rowIndex, int columnIndex) {
            ParameterRecord r = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> r.name;
                case 1 -> String.join(", ", r.sources);
                case 2 -> String.join(", ", r.types);
                case 3 -> String.join(", ", r.exampleValues);
                case 4 -> r.count;
                case 5 -> r.onlyInCode;
                case 6 -> r.patternsFromJs.isEmpty() ? "" : String.join(", ", r.patternsFromJs);
                default -> "";
            };
        }
    }

    private static class EndpointTableModel extends AbstractTableModel {
        private final String[] cols = {"Endpoint", "Source", "Type", "Referer", "FirstSeen", "Pattern"};
        private List<EndpointRecord> rows = new ArrayList<>();

        public void setRows(List<EndpointRecord> records) { this.rows = new ArrayList<>(records == null ? List.of() : records); fireTableDataChanged(); }
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int column) { return cols[column]; }
        @Override public Object getValueAt(int rowIndex, int columnIndex) {
            EndpointRecord r = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> displayEndpoint(r);
                case 1 -> r.source == null ? "" : r.source;
                case 2 -> r.type;
                case 3 -> r.referer == null ? "" : r.referer;
                case 4 -> new java.util.Date(r.firstSeen);
                case 5 -> r.pattern == null ? "" : r.pattern;
                default -> "";
            };
        }

        private String displayEndpoint(EndpointRecord r) {
            String val = r.endpointString == null ? "" : r.endpointString;
            if (r.type == EndpointRecord.Type.TEMPLATE) {
                return val.replace("EXPR", "<VAR>");
            }
            if (r.type == EndpointRecord.Type.CONCAT) {
                int firstSlash = val.indexOf('/');
                if (firstSlash > 0) {
                    String head = val.substring(0, firstSlash);
                    if (head.matches("[A-Za-z0-9_\\$\\.]+")) {
                        return "<VAR>" + val.substring(firstSlash);
                    }
                }
                int lastSlash = val.lastIndexOf('/');
                if (lastSlash >= 0 && lastSlash + 1 < val.length()) {
                    String tail = val.substring(lastSlash + 1);
                    if (tail.matches("[A-Za-z0-9_\\$\\.]+")) {
                        return val.substring(0, lastSlash + 1) + "<VAR>";
                    }
                }
            }
            return val;
        }
    }

    private static class JsluiceTableModel extends AbstractTableModel {
        private final String[] cols = {"url", "method", "type", "JS Source", "Referer/Origin", "queryParams", "bodyParams", "contentType", "headers"};
        private java.util.List<JsluiceUrlRecord> rows = new java.util.ArrayList<>();

        public void setRows(java.util.List<JsluiceUrlRecord> r) { this.rows = new java.util.ArrayList<>(r == null ? java.util.List.of() : r); fireTableDataChanged(); }
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int column) { return cols[column]; }
        @Override public Object getValueAt(int rowIndex, int columnIndex) {
            JsluiceUrlRecord r = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> r.url == null ? "" : r.url;
                case 1 -> r.method == null ? "" : r.method;
                case 2 -> r.type == null ? "" : r.type;
                case 3 -> r.sourceJsUrl == null ? "" : r.sourceJsUrl;
                case 4 -> r.refererUrl == null ? "" : r.refererUrl;
                case 5 -> r.queryParams == null || r.queryParams.isEmpty() ? "" : String.join(", ", r.queryParams);
                case 6 -> r.bodyParams == null || r.bodyParams.isEmpty() ? "" : String.join(", ", r.bodyParams);
                case 7 -> r.contentType == null ? "" : r.contentType;
                case 8 -> r.headers == null || r.headers.isEmpty() ? "" : r.headers.toString();
                default -> "";
            };
        }
    }
}
