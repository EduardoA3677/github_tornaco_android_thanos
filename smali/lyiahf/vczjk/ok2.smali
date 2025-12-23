.class public abstract Llyiahf/vczjk/ok2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:I

.field public static final OooO0O0:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const/16 v0, 0xe6

    const/16 v1, 0xff

    invoke-static {v0, v1, v1, v1}, Landroid/graphics/Color;->argb(IIII)I

    move-result v0

    sput v0, Llyiahf/vczjk/ok2;->OooO00o:I

    const/16 v0, 0x80

    const/16 v1, 0x1b

    invoke-static {v0, v1, v1, v1}, Landroid/graphics/Color;->argb(IIII)I

    move-result v0

    sput v0, Llyiahf/vczjk/ok2;->OooO0O0:I

    return-void
.end method

.method public static final OooO00o(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/fd9;Llyiahf/vczjk/fd9;)V
    .locals 8

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v5

    const-string v0, "window.decorView"

    invoke-static {v5, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v5}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    const-string v1, "view.resources"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, p1, Llyiahf/vczjk/fd9;->OooO0OO:Llyiahf/vczjk/oe3;

    invoke-interface {v2, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v6

    invoke-virtual {v5}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p2, Llyiahf/vczjk/fd9;->OooO0OO:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v7

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1e

    if-lt v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/tk2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    :goto_0
    move-object v1, v0

    goto :goto_1

    :cond_0
    const/16 v1, 0x1d

    if-lt v0, v1, :cond_1

    new-instance v0, Llyiahf/vczjk/sk2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    goto :goto_0

    :cond_1
    const/16 v1, 0x1c

    if-lt v0, v1, :cond_2

    new-instance v0, Llyiahf/vczjk/rk2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    goto :goto_0

    :cond_2
    const/16 v1, 0x1a

    if-lt v0, v1, :cond_3

    new-instance v0, Llyiahf/vczjk/qk2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    goto :goto_0

    :cond_3
    new-instance v0, Llyiahf/vczjk/pk2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    goto :goto_0

    :goto_1
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object v4

    const-string v0, "window"

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v2, p1

    move-object v3, p2

    invoke-virtual/range {v1 .. v7}, Llyiahf/vczjk/qqa;->Oooo(Llyiahf/vczjk/fd9;Llyiahf/vczjk/fd9;Landroid/view/Window;Landroid/view/View;ZZ)V

    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object p0

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Llyiahf/vczjk/qqa;->OooOOO0(Landroid/view/Window;)V

    return-void
.end method
