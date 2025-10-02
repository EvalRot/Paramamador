package burp.paramamador.ui;

import burp.paramamador.Settings;
import burp.paramamador.datastore.DataStore;
import burp.paramamador.datastore.EndpointRecord;
import burp.paramamador.datastore.ParameterRecord;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.nio.file.Path;
import java.util.List;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Main suite tab containing three sub-tabs: Parameters, Endpoints, Settings.
 */
public class ParamamadorTab {
    private final DataStore store;
    private final Settings settings;
    private final Runnable rescanAction;
    private final Runnable saveAction;

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

    // Settings controls
    private final JCheckBox scopeOnly = new JCheckBox("Scope only");
    private final JSpinner autoSaveSec = new JSpinner(new SpinnerNumberModel(300, 30, 3600, 10));
    private final JSpinner maxInlineKb = new JSpinner(new SpinnerNumberModel(200, 10, 10_000, 10));
    private final JSpinner maxQueue = new JSpinner(new SpinnerNumberModel(200, 50, 10_000, 10));
    private final JTextField exportDir = new JTextField();
    private final DefaultListModel<String> ignoredModel = new DefaultListModel<>();

    public ParamamadorTab(DataStore store, Settings settings, Runnable rescanAction, Runnable saveAction) {
        this.store = store;
        this.settings = settings;
        this.rescanAction = rescanAction;
        this.saveAction = saveAction;

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Parameters", buildParametersPanel());
        tabs.addTab("Endpoints", buildEndpointsPanel());
        tabs.addTab("NotSure", buildNotSurePanel());
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

        refreshAll();
    }

    public Component getComponent() { return root; }

    public void refreshAll() {
        SwingUtilities.invokeLater(() -> {
            paramModel.setRows(store.snapshotParameters());
            endpointModel.setRows(store.snapshotEndpoints());
            notSureModel.setRows(store.snapshotNotSureEndpoints());
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
            for (String s : settings.getIgnoredPatterns()) ignoredModel.addElement(s);
        });
    }

    private JPanel buildParametersPanel() {
        JPanel p = new JPanel(new BorderLayout());
        JTextField filter = new JTextField();
        JButton copy = new JButton("Copy");
        JButton export = new JButton("Export selected");

        paramTable.setAutoCreateRowSorter(true);
        paramTable.setRowSorter(paramSorter);

        filter.addActionListener(e -> {
            String text = filter.getText();
            if (text == null || text.isBlank()) paramSorter.setRowFilter(null);
            else paramSorter.setRowFilter(RowFilter.regexFilter(Pattern.quote(text), 0));
        });

        copy.addActionListener((ActionEvent e) -> {
            int[] rows = paramTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int r : rows) {
                int m = paramTable.convertRowIndexToModel(r);
                sb.append(paramModel.rows.get(m).name).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
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
        JButton sendToRepeater = new JButton("Send to Repeater");
        JButton openInProxy = new JButton("Open in Proxy History");
        JButton ignore = new JButton("Ignore");

        endpointTable.setAutoCreateRowSorter(true);
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

        filter.addActionListener(e -> {
            String text = filter.getText();
            if (text == null || text.isBlank()) endpointSorter.setRowFilter(null);
            else endpointSorter.setRowFilter(RowFilter.regexFilter(Pattern.quote(text), 0));
        });

        ignore.addActionListener(e -> {
            int r = endpointTable.getSelectedRow();
            if (r >= 0) {
                int m = endpointTable.convertRowIndexToModel(r);
                String val = endpointModel.rows.get(m).endpointString;
                // ignore by pattern equals the value
                // in a real impl we might allow editing regex; here we add the full string
                settings.addIgnoredPattern(val);
                refreshSettingsFromModel();
            }
        });

        JPanel top = new JPanel(new BorderLayout());
        top.add(new JLabel("Filter:"), BorderLayout.WEST);
        top.add(filter, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(sendToRepeater);
        actions.add(openInProxy);
        actions.add(ignore);
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

        notSureTable.setAutoCreateRowSorter(true);
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

        filter.addActionListener(e -> {
            String text = filter.getText();
            if (text == null || text.isBlank()) notSureSorter.setRowFilter(null);
            else notSureSorter.setRowFilter(RowFilter.regexFilter(Pattern.quote(text), 0));
        });

        copy.addActionListener((ActionEvent e) -> {
            int[] rows = notSureTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int r : rows) {
                int m = notSureTable.convertRowIndexToModel(r);
                sb.append(notSureModel.rows.get(m).endpointString).append('\n');
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
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
        settings.getIgnoredPatterns().forEach(ignoredModel::addElement);
        JList<String> ignored = new JList<>(ignoredModel);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField newPattern = new JTextField(20);
        JButton add = new JButton("Add");
        JButton remove = new JButton("Remove selected");
        add.addActionListener(e -> {
            if (!newPattern.getText().isBlank()) {
                settings.addIgnoredPattern(newPattern.getText().trim());
                ignoredModel.addElement(newPattern.getText().trim());
                newPattern.setText("");
            }
        });
        remove.addActionListener(e -> {
            for (String s : ignored.getSelectedValuesList()) {
                settings.removeIgnoredPattern(s);
                ignoredModel.removeElement(s);
            }
        });
        buttons.add(new JLabel("Pattern:"));
        buttons.add(newPattern);
        buttons.add(add);
        buttons.add(remove);
        c.gridx = 1; c.gridy = row; form.add(new JScrollPane(ignored), c); row++;
        c.gridx = 1; c.gridy = row; form.add(buttons, c); row++;

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton apply = new JButton("Apply");
        JButton clear = new JButton("Clear data");
        JButton rescan = new JButton("Rescan Site Tree");
        JButton save = new JButton("Save now");

        apply.addActionListener(e -> applySettings());
        clear.addActionListener(e -> clearData());
        rescan.addActionListener(e -> rescanAction.run());
        save.addActionListener(e -> saveAction.run());

        actions.add(apply); actions.add(clear); actions.add(rescan); actions.add(save);

        p.add(form, BorderLayout.CENTER);
        p.add(actions, BorderLayout.SOUTH);
        return p;
    }

    private void applySettings() {
        settings.setScopeOnly(scopeOnly.isSelected());
        settings.setAutoSaveSeconds((Integer) autoSaveSec.getValue());
        settings.setMaxInlineJsKb((Integer) maxInlineKb.getValue());
        settings.setMaxQueueSize((Integer) maxQueue.getValue());
        settings.setExportDir(Path.of(exportDir.getText()));
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
        private final String[] cols = {"Endpoint", "Sources", "Type", "InScope", "FirstSeen", "Pattern"};
        private List<EndpointRecord> rows = new ArrayList<>();

        public void setRows(List<EndpointRecord> r) { this.rows = new ArrayList<>(r); fireTableDataChanged(); }
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int column) { return cols[column]; }
        @Override public Object getValueAt(int rowIndex, int columnIndex) {
            EndpointRecord r = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> r.endpointString;
                case 1 -> String.join(", ", r.sources);
                case 2 -> r.type;
                case 3 -> r.inScope;
                case 4 -> new java.util.Date(r.firstSeen);
                case 5 -> r.pattern == null ? "" : r.pattern;
                default -> "";
            };
        }
    }
}
