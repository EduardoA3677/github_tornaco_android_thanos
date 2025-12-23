.class public final Lnow/fortuitous/thanos/sf/SFActivity;
.super Lnow/fortuitous/thanos/sf/Hilt_SFActivity;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0007\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0004"
    }
    d2 = {
        "Lnow/fortuitous/thanos/sf/SFActivity;",
        "Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;",
        "<init>",
        "()V",
        "app_prcRelease"
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
.field public static final synthetic OoooO:I


# instance fields
.field public final OoooO0O:Llyiahf/vczjk/cp8;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Lnow/fortuitous/thanos/sf/Hilt_SFActivity;-><init>()V

    new-instance v0, Llyiahf/vczjk/cp8;

    invoke-direct {v0, p0}, Llyiahf/vczjk/cp8;-><init>(Lgithub/tornaco/android/thanos/theme/ThemeActivity;)V

    iput-object v0, p0, Lnow/fortuitous/thanos/sf/SFActivity;->OoooO0O:Llyiahf/vczjk/cp8;

    return-void
.end method


# virtual methods
.method public final OooOoOO(ILlyiahf/vczjk/rf1;)V
    .locals 4

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, -0x49e48315

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    or-int/2addr v0, p1

    and-int/lit8 v2, v0, 0x3

    if-ne v2, v1, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_2
    :goto_1
    sget-object v1, Llyiahf/vczjk/z35;->OooO00o:Llyiahf/vczjk/l39;

    iget-object v2, p0, Lnow/fortuitous/thanos/sf/SFActivity;->OoooO0O:Llyiahf/vczjk/cp8;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/l39;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/nz7;

    const/4 v3, 0x0

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/nz7;-><init>(Lnow/fortuitous/thanos/sf/SFActivity;I)V

    const v3, 0x20f031ab

    invoke-static {v3, v2, p2}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/16 v3, 0x38

    invoke-static {v1, v2, p2, v3}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    and-int/lit8 v0, v0, 0xe

    invoke-static {p0, p2, v0}, Llyiahf/vczjk/kh6;->OooO0Oo(Lnow/fortuitous/thanos/sf/SFActivity;Llyiahf/vczjk/rf1;I)V

    const/4 v0, 0x0

    invoke-static {v0, p2}, Llyiahf/vczjk/nqa;->OooO0OO(ILlyiahf/vczjk/rf1;)V

    :goto_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_3

    new-instance v0, Llyiahf/vczjk/lz7;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/lz7;-><init>(Lnow/fortuitous/thanos/sf/SFActivity;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method
