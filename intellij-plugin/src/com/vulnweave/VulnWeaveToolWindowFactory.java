package com.vulnweave;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentManager;

import javax.swing.JComponent;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Creates the VulnWeave tool-window content without emitting a bytecode call
 * directly against ContentFactory.createContent(). IntelliJ 2026 changed
 * ContentFactory from a class to an interface, which makes binaries compiled
 * with invokevirtual against older IDEs fail with IncompatibleClassChangeError.
 *
 * ContentManager#getFactory() and ContentFactory#createContent() remain public
 * APIs; reflection here is intentionally limited to that compatibility seam so
 * the same plugin binary can run across 2025.1+ and 2026.x.
 */
public final class VulnWeaveToolWindowFactory implements ToolWindowFactory {
    @Override
    public void createToolWindowContent(Project project, ToolWindow toolWindow) {
        VulnWeavePanel panel = new VulnWeavePanel(project);
        ContentManager contentManager = toolWindow.getContentManager();
        Content content = createContentCompat(contentManager, panel);
        contentManager.addContent(content);
    }

    private static Content createContentCompat(ContentManager contentManager, JComponent panel) {
        try {
            Method getFactory = ContentManager.class.getMethod("getFactory");
            Object factory = getFactory.invoke(contentManager);
            if (factory == null) {
                throw new IllegalStateException("IntelliJ ContentManager returned a null ContentFactory");
            }

            Class<?> contentFactoryApi = Class.forName(
                    "com.intellij.ui.content.ContentFactory",
                    true,
                    VulnWeaveToolWindowFactory.class.getClassLoader());
            Method createContent = contentFactoryApi.getMethod(
                    "createContent", JComponent.class, String.class, boolean.class);
            Object created = createContent.invoke(factory, panel, "", false);
            if (!(created instanceof Content)) {
                throw new IllegalStateException("IntelliJ ContentFactory returned an unexpected content object");
            }
            return (Content) created;
        } catch (InvocationTargetException ex) {
            Throwable cause = ex.getCause() == null ? ex : ex.getCause();
            throw new IllegalStateException("Unable to create VulnWeave tool-window content: " + cause, cause);
        } catch (ReflectiveOperationException | LinkageError ex) {
            throw new IllegalStateException(
                    "Unable to create VulnWeave tool-window content on this IntelliJ Platform version", ex);
        }
    }
}
