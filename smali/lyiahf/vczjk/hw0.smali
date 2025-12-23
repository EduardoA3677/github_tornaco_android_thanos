.class public final Llyiahf/vczjk/hw0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/rn9;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:Llyiahf/vczjk/wv0;

.field public final synthetic OooOOo:F

.field public final synthetic OooOOo0:Z

.field public final synthetic OooOOoo:Llyiahf/vczjk/di6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/rn9;JLlyiahf/vczjk/wv0;ZFLlyiahf/vczjk/di6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hw0;->OooOOO0:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/hw0;->OooOOO:Llyiahf/vczjk/rn9;

    iput-wide p3, p0, Llyiahf/vczjk/hw0;->OooOOOO:J

    iput-object p5, p0, Llyiahf/vczjk/hw0;->OooOOOo:Llyiahf/vczjk/wv0;

    iput-boolean p6, p0, Llyiahf/vczjk/hw0;->OooOOo0:Z

    iput p7, p0, Llyiahf/vczjk/hw0;->OooOOo:F

    iput-object p8, p0, Llyiahf/vczjk/hw0;->OooOOoo:Llyiahf/vczjk/di6;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

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

    move-object v11, p1

    check-cast v11, Llyiahf/vczjk/zf1;

    invoke-virtual {v11, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/hw0;->OooOOOo:Llyiahf/vczjk/wv0;

    iget-boolean p2, p0, Llyiahf/vczjk/hw0;->OooOOo0:Z

    if-eqz p2, :cond_1

    iget-wide v0, p1, Llyiahf/vczjk/wv0;->OooO0OO:J

    :goto_1
    move-wide v5, v0

    goto :goto_2

    :cond_1
    iget-wide v0, p1, Llyiahf/vczjk/wv0;->OooO0oO:J

    goto :goto_1

    :goto_2
    if-eqz p2, :cond_2

    iget-wide p1, p1, Llyiahf/vczjk/wv0;->OooO0Oo:J

    :goto_3
    move-wide v7, p1

    goto :goto_4

    :cond_2
    iget-wide p1, p1, Llyiahf/vczjk/wv0;->OooO0oo:J

    goto :goto_3

    :goto_4
    iget-object v1, p0, Llyiahf/vczjk/hw0;->OooOOO0:Llyiahf/vczjk/a91;

    iget-wide v3, p0, Llyiahf/vczjk/hw0;->OooOOOO:J

    iget v9, p0, Llyiahf/vczjk/hw0;->OooOOo:F

    iget-object v2, p0, Llyiahf/vczjk/hw0;->OooOOO:Llyiahf/vczjk/rn9;

    iget-object v10, p0, Llyiahf/vczjk/hw0;->OooOOoo:Llyiahf/vczjk/di6;

    const/16 v12, 0x6000

    invoke-static/range {v1 .. v12}, Llyiahf/vczjk/jw0;->OooO0OO(Llyiahf/vczjk/a91;Llyiahf/vczjk/rn9;JJJFLlyiahf/vczjk/di6;Llyiahf/vczjk/rf1;I)V

    goto :goto_5

    :cond_3
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
