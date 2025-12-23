.class public final Llyiahf/vczjk/g58;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/j58;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j58;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/g58;->this$0:Llyiahf/vczjk/j58;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooO00o()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/g58;->OooO0oO()Ljava/lang/Boolean;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oO()Ljava/lang/Boolean;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/g58;->this$0:Llyiahf/vczjk/j58;

    invoke-static {v0}, Llyiahf/vczjk/j58;->OooO00o(Llyiahf/vczjk/j58;)Ljava/lang/Class;

    move-result-object v0

    const-class v1, Landroid/content/Context;

    const-class v2, Landroidx/window/extensions/core/util/function/Consumer;

    filled-new-array {v1, v2}, [Ljava/lang/Class;

    move-result-object v1

    const-string v2, "addWindowLayoutInfoListener"

    invoke-virtual {v0, v2, v1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v1

    const-class v2, Landroidx/window/extensions/core/util/function/Consumer;

    filled-new-array {v2}, [Ljava/lang/Class;

    move-result-object v2

    const-string v3, "removeWindowLayoutInfoListener"

    invoke-virtual {v0, v3, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v1

    invoke-static {v1}, Ljava/lang/reflect/Modifier;->isPublic(I)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v0

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isPublic(I)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0
.end method
