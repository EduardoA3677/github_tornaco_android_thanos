.class public abstract Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;
.super Lgithub/tornaco/android/thanos/theme/ThemeActivity;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\'\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0004"
    }
    d2 = {
        "Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;",
        "Lgithub/tornaco/android/thanos/theme/ThemeActivity;",
        "<init>",
        "()V",
        "module_common_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final synthetic Oooo0oO:I


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/theme/ThemeActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public abstract OooOoOO(ILlyiahf/vczjk/rf1;)V
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 6

    const/4 v0, 0x1

    invoke-super {p0, p1}, Lgithub/tornaco/android/thanos/theme/ThemeActivity;->onCreate(Landroid/os/Bundle;)V

    sget p1, Llyiahf/vczjk/ok2;->OooO00o:I

    sget-object p1, Llyiahf/vczjk/o68;->Oooo0:Llyiahf/vczjk/o68;

    new-instance v1, Llyiahf/vczjk/fd9;

    const/4 v2, 0x0

    invoke-direct {v1, v2, v2, p1}, Llyiahf/vczjk/fd9;-><init>(IILlyiahf/vczjk/oe3;)V

    new-instance v3, Llyiahf/vczjk/fd9;

    sget v4, Llyiahf/vczjk/ok2;->OooO00o:I

    sget v5, Llyiahf/vczjk/ok2;->OooO0O0:I

    invoke-direct {v3, v4, v5, p1}, Llyiahf/vczjk/fd9;-><init>(IILlyiahf/vczjk/oe3;)V

    invoke-static {p0, v1, v3}, Llyiahf/vczjk/ok2;->OooO00o(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/fd9;Llyiahf/vczjk/fd9;)V

    new-instance p1, Llyiahf/vczjk/ne1;

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/ne1;-><init>(Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;I)V

    new-instance v1, Llyiahf/vczjk/a91;

    const v3, 0x6d09ed91

    invoke-direct {v1, v3, p1, v0}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    new-instance p1, Llyiahf/vczjk/rq9;

    invoke-virtual {p0}, Landroidx/appcompat/app/AppCompatActivity;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    invoke-virtual {v3}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v3

    const-string v4, "getConfiguration(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3}, Llyiahf/vczjk/ll6;->OooOO0O(Landroid/content/res/Configuration;)Z

    move-result v3

    invoke-direct {p1, v3, v2}, Llyiahf/vczjk/rq9;-><init>(ZZ)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    invoke-static {p0}, Llyiahf/vczjk/u34;->OooOoO(Llyiahf/vczjk/uy4;)Llyiahf/vczjk/py4;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/xe1;

    const/4 v4, 0x0

    invoke-direct {v3, p0, p1, v4}, Llyiahf/vczjk/xe1;-><init>(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    const/4 v5, 0x3

    invoke-static {v2, v4, v4, v3, v5}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v2, Llyiahf/vczjk/b6;

    const/16 v3, 0xe

    invoke-direct {v2, v3, p1, v1}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/a91;

    const v1, 0x21ccf981

    invoke-direct {p1, v1, v2, v0}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-static {p0, p1}, Llyiahf/vczjk/x61;->OooO00o(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/a91;)V

    return-void
.end method
