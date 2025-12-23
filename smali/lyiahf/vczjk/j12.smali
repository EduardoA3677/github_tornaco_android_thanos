.class public final Llyiahf/vczjk/j12;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/j12;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/j12;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/j12;->OooO00o:Llyiahf/vczjk/j12;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/rf1;I)V
    .locals 6

    move-object v3, p2

    check-cast v3, Llyiahf/vczjk/zf1;

    const p2, 0x5d549e6c

    invoke-virtual {v3, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v3, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    const/4 v0, 0x2

    if-eqz p2, :cond_0

    const/4 p2, 0x4

    goto :goto_0

    :cond_0
    move p2, v0

    :goto_0
    or-int/2addr p2, p3

    and-int/lit8 v1, p2, 0x3

    const/4 v2, 0x1

    if-eq v1, v0, :cond_1

    move v0, v2

    goto :goto_1

    :cond_1
    const/4 v0, 0x0

    :goto_1
    and-int/2addr p2, v2

    invoke-virtual {v3, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_2

    new-instance p2, Llyiahf/vczjk/f5;

    const/16 v0, 0x9

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    const v0, 0x455a0383

    invoke-static {v0, p2, v3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/4 v5, 0x0

    iget-object p2, p1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    move-object v1, p2

    check-cast v1, Llyiahf/vczjk/ab2;

    iget-object p2, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/le3;

    const/16 v4, 0x180

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/dn8;->OooOOo0(Llyiahf/vczjk/le3;Llyiahf/vczjk/ab2;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    goto :goto_2

    :cond_2
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_3

    new-instance v0, Llyiahf/vczjk/e2;

    const/16 v1, 0xc

    invoke-direct {v0, p0, p1, p3, v1}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method
