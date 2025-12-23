.class public final Llyiahf/vczjk/j58;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/lang/ClassLoader;

.field public final OooO0O0:Llyiahf/vczjk/tqa;

.field public final OooO0OO:Llyiahf/vczjk/b58;


# direct methods
.method public constructor <init>(Ljava/lang/ClassLoader;Llyiahf/vczjk/tqa;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/j58;->OooO00o:Ljava/lang/ClassLoader;

    iput-object p2, p0, Llyiahf/vczjk/j58;->OooO0O0:Llyiahf/vczjk/tqa;

    new-instance p2, Llyiahf/vczjk/b58;

    invoke-direct {p2, p1}, Llyiahf/vczjk/b58;-><init>(Ljava/lang/ClassLoader;)V

    iput-object p2, p0, Llyiahf/vczjk/j58;->OooO0OO:Llyiahf/vczjk/b58;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/j58;)Ljava/lang/Class;
    .locals 1

    iget-object p0, p0, Llyiahf/vczjk/j58;->OooO00o:Ljava/lang/ClassLoader;

    const-string v0, "androidx.window.extensions.layout.WindowLayoutComponent"

    invoke-virtual {p0, v0}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p0

    const-string v0, "loadClass(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method


# virtual methods
.method public final OooO0O0()Landroidx/window/extensions/layout/WindowLayoutComponent;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/j58;->OooO0OO:Llyiahf/vczjk/b58;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/z48;

    invoke-direct {v1, v0}, Llyiahf/vczjk/z48;-><init>(Llyiahf/vczjk/b58;)V

    const/4 v2, 0x0

    :try_start_0
    invoke-virtual {v1}, Llyiahf/vczjk/z48;->OooO00o()Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_0 .. :try_end_0} :catch_0

    new-instance v1, Llyiahf/vczjk/a58;

    invoke-direct {v1, v0}, Llyiahf/vczjk/a58;-><init>(Llyiahf/vczjk/b58;)V

    const-string v0, "WindowExtensionsProvider#getWindowExtensions is not valid"

    invoke-static {v0, v1}, Llyiahf/vczjk/dr6;->OooOoO(Ljava/lang/String;Llyiahf/vczjk/le3;)Z

    move-result v0

    if-eqz v0, :cond_3

    new-instance v0, Llyiahf/vczjk/i58;

    invoke-direct {v0, p0}, Llyiahf/vczjk/i58;-><init>(Llyiahf/vczjk/j58;)V

    const-string v1, "WindowExtensions#getWindowLayoutComponent is not valid"

    invoke-static {v1, v0}, Llyiahf/vczjk/dr6;->OooOoO(Ljava/lang/String;Llyiahf/vczjk/le3;)Z

    move-result v0

    if-eqz v0, :cond_3

    new-instance v0, Llyiahf/vczjk/d58;

    invoke-direct {v0, p0}, Llyiahf/vczjk/d58;-><init>(Llyiahf/vczjk/j58;)V

    const-string v1, "FoldingFeature class is not valid"

    invoke-static {v1, v0}, Llyiahf/vczjk/dr6;->OooOoO(Ljava/lang/String;Llyiahf/vczjk/le3;)Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-static {}, Llyiahf/vczjk/ru2;->OooO00o()I

    move-result v0

    const/4 v1, 0x1

    if-ge v0, v1, :cond_0

    goto :goto_0

    :cond_0
    if-ne v0, v1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/j58;->OooO0OO()Z

    move-result v2

    goto :goto_0

    :cond_1
    const/4 v3, 0x5

    if-ge v0, v3, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/j58;->OooO0Oo()Z

    move-result v2

    goto :goto_0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/j58;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_3

    new-instance v0, Llyiahf/vczjk/c58;

    invoke-direct {v0, p0}, Llyiahf/vczjk/c58;-><init>(Llyiahf/vczjk/j58;)V

    const-string v3, "DisplayFoldFeature is not valid"

    invoke-static {v3, v0}, Llyiahf/vczjk/dr6;->OooOoO(Ljava/lang/String;Llyiahf/vczjk/le3;)Z

    move-result v0

    if-eqz v0, :cond_3

    new-instance v0, Llyiahf/vczjk/h58;

    invoke-direct {v0, p0}, Llyiahf/vczjk/h58;-><init>(Llyiahf/vczjk/j58;)V

    const-string v3, "SupportedWindowFeatures is not valid"

    invoke-static {v3, v0}, Llyiahf/vczjk/dr6;->OooOoO(Ljava/lang/String;Llyiahf/vczjk/le3;)Z

    move-result v0

    if-eqz v0, :cond_3

    new-instance v0, Llyiahf/vczjk/e58;

    invoke-direct {v0, p0}, Llyiahf/vczjk/e58;-><init>(Llyiahf/vczjk/j58;)V

    const-string v3, "WindowLayoutComponent#getSupportedWindowFeatures is not valid"

    invoke-static {v3, v0}, Llyiahf/vczjk/dr6;->OooOoO(Ljava/lang/String;Llyiahf/vczjk/le3;)Z

    move-result v0

    if-eqz v0, :cond_3

    move v2, v1

    :catch_0
    :cond_3
    :goto_0
    const/4 v0, 0x0

    if-eqz v2, :cond_4

    :try_start_1
    invoke-static {}, Landroidx/window/extensions/WindowExtensionsProvider;->getWindowExtensions()Landroidx/window/extensions/WindowExtensions;

    move-result-object v1

    invoke-interface {v1}, Landroidx/window/extensions/WindowExtensions;->getWindowLayoutComponent()Landroidx/window/extensions/layout/WindowLayoutComponent;

    move-result-object v0
    :try_end_1
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_1 .. :try_end_1} :catch_1

    :catch_1
    :cond_4
    return-object v0
.end method

.method public final OooO0OO()Z
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "WindowLayoutComponent#addWindowLayoutInfoListener("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-class v1, Landroid/app/Activity;

    const-string v2, ", java.util.function.Consumer) is not valid"

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/f58;

    invoke-direct {v1, p0}, Llyiahf/vczjk/f58;-><init>(Llyiahf/vczjk/j58;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/dr6;->OooOoO(Ljava/lang/String;Llyiahf/vczjk/le3;)Z

    move-result v0

    return v0
.end method

.method public final OooO0Oo()Z
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/j58;->OooO0OO()Z

    move-result v0

    if-eqz v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "WindowLayoutComponent#addWindowLayoutInfoListener("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-class v1, Landroid/content/Context;

    const-string v2, ", androidx.window.extensions.core.util.function.Consumer) is not valid"

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/g58;

    invoke-direct {v1, p0}, Llyiahf/vczjk/g58;-><init>(Llyiahf/vczjk/j58;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/dr6;->OooOoO(Ljava/lang/String;Llyiahf/vczjk/le3;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
