.class public final Landroidx/appcompat/widget/OooO0o;
.super Landroidx/appcompat/widget/ListPopupWindow;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ch5;


# static fields
.field public static final Oooo:Ljava/lang/reflect/Method;


# instance fields
.field public Oooo0oo:Llyiahf/vczjk/tg7;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    :try_start_0
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-gt v0, v1, :cond_0

    const-class v0, Landroid/widget/PopupWindow;

    const-string v1, "setTouchModal"

    sget-object v2, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    filled-new-array {v2}, [Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/widget/OooO0o;->Oooo:Ljava/lang/reflect/Method;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    const-string v0, "MenuPopupWindow"

    const-string v1, "Could not find method setTouchModal() on PopupWindow. Oh well."

    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :cond_0
    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/sg5;Llyiahf/vczjk/dh5;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/widget/OooO0o;->Oooo0oo:Llyiahf/vczjk/tg7;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/tg7;->OooO0Oo(Llyiahf/vczjk/sg5;Llyiahf/vczjk/dh5;)V

    :cond_0
    return-void
.end method

.method public final OooOOO0(Llyiahf/vczjk/sg5;Llyiahf/vczjk/dh5;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/widget/OooO0o;->Oooo0oo:Llyiahf/vczjk/tg7;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/tg7;->OooOOO0(Llyiahf/vczjk/sg5;Llyiahf/vczjk/dh5;)V

    :cond_0
    return-void
.end method

.method public final OooOOo0(Landroid/content/Context;Z)Llyiahf/vczjk/xi2;
    .locals 1

    new-instance v0, Llyiahf/vczjk/zh5;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/zh5;-><init>(Landroid/content/Context;Z)V

    invoke-virtual {v0, p0}, Llyiahf/vczjk/zh5;->setHoverListener(Llyiahf/vczjk/ch5;)V

    return-object v0
.end method
