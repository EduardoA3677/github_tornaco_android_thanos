.class public final Llyiahf/vczjk/u33;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/rn9;

.field public final synthetic OooOOO0:J

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/rn9;FLlyiahf/vczjk/a91;)V
    .locals 1

    sget v0, Llyiahf/vczjk/wu2;->OooO00o:F

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Llyiahf/vczjk/u33;->OooOOO0:J

    iput-object p3, p0, Llyiahf/vczjk/u33;->OooOOO:Llyiahf/vczjk/rn9;

    iput p4, p0, Llyiahf/vczjk/u33;->OooOOOO:F

    iput-object p5, p0, Llyiahf/vczjk/u33;->OooOOOo:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_1

    new-instance p1, Llyiahf/vczjk/wf0;

    iget-object p2, p0, Llyiahf/vczjk/u33;->OooOOOo:Llyiahf/vczjk/a91;

    sget v0, Llyiahf/vczjk/wu2;->OooO00o:F

    iget v0, p0, Llyiahf/vczjk/u33;->OooOOOO:F

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/wf0;-><init>(FLlyiahf/vczjk/a91;)V

    const p2, -0x6957d1e1

    invoke-static {p2, p1, v5}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    iget-object v3, p0, Llyiahf/vczjk/u33;->OooOOO:Llyiahf/vczjk/rn9;

    const/16 v6, 0x180

    iget-wide v1, p0, Llyiahf/vczjk/u33;->OooOOO0:J

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/tp6;->OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
