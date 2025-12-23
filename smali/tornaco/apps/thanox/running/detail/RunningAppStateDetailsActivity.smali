.class public final Ltornaco/apps/thanox/running/detail/RunningAppStateDetailsActivity;
.super Ltornaco/apps/thanox/running/detail/Hilt_RunningAppStateDetailsActivity;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0007\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0004"
    }
    d2 = {
        "Ltornaco/apps/thanox/running/detail/RunningAppStateDetailsActivity;",
        "Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;",
        "<init>",
        "()V",
        "ui_prcRelease"
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
.field public static final synthetic OoooO0O:I


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ltornaco/apps/thanox/running/detail/Hilt_RunningAppStateDetailsActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooOoOO(ILlyiahf/vczjk/rf1;)V
    .locals 4

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, -0x374db567

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x2

    const/4 v2, 0x4

    if-eqz v0, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    or-int/2addr v0, p1

    and-int/lit8 v3, v0, 0x3

    if-ne v3, v1, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_2
    :goto_1
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    move-result-object v1

    const-string v3, "details"

    invoke-virtual {v1, v3}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object v1

    check-cast v1, Ltornaco/apps/thanox/running/detail/RunningAppStateDetails;

    if-nez v1, :cond_3

    goto :goto_3

    :cond_3
    const v3, 0x4c5de2

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v0, v0, 0xe

    const/4 v3, 0x0

    if-eq v0, v2, :cond_4

    move v0, v3

    goto :goto_2

    :cond_4
    const/4 v0, 0x1

    :goto_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v0, :cond_5

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v0, :cond_6

    :cond_5
    new-instance v2, Llyiahf/vczjk/w45;

    const/16 v0, 0x11

    invoke-direct {v2, p0, v0}, Llyiahf/vczjk/w45;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v2, p2, v3}, Llyiahf/vczjk/ht6;->OooO0OO(Ltornaco/apps/thanox/running/detail/RunningAppStateDetails;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_3
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_7

    new-instance v0, Llyiahf/vczjk/sj5;

    const/16 v1, 0x14

    invoke-direct {v0, p1, v1, p0}, Llyiahf/vczjk/sj5;-><init>(IILjava/lang/Object;)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void
.end method
