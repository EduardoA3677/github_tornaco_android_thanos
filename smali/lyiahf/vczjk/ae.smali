.class public final Llyiahf/vczjk/ae;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ss5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOOo:Llyiahf/vczjk/z98;

.field public final synthetic OooOOo:J

.field public final synthetic OooOOo0:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOoo:F

.field public final synthetic OooOo0:Llyiahf/vczjk/a91;

.field public final synthetic OooOo00:F


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ss5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/z98;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ae;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/ae;->OooOOO:Llyiahf/vczjk/ss5;

    iput-object p3, p0, Llyiahf/vczjk/ae;->OooOOOO:Llyiahf/vczjk/qs5;

    iput-object p4, p0, Llyiahf/vczjk/ae;->OooOOOo:Llyiahf/vczjk/z98;

    iput-object p5, p0, Llyiahf/vczjk/ae;->OooOOo0:Llyiahf/vczjk/qj8;

    iput-wide p6, p0, Llyiahf/vczjk/ae;->OooOOo:J

    iput p8, p0, Llyiahf/vczjk/ae;->OooOOoo:F

    iput p9, p0, Llyiahf/vczjk/ae;->OooOo00:F

    iput-object p10, p0, Llyiahf/vczjk/ae;->OooOo0:Llyiahf/vczjk/a91;

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

    if-eqz p1, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/ae;->OooOOO:Llyiahf/vczjk/ss5;

    iget-object v10, p0, Llyiahf/vczjk/ae;->OooOo0:Llyiahf/vczjk/a91;

    const/16 v12, 0x180

    iget-object v1, p0, Llyiahf/vczjk/ae;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-object v3, p0, Llyiahf/vczjk/ae;->OooOOOO:Llyiahf/vczjk/qs5;

    iget-object v4, p0, Llyiahf/vczjk/ae;->OooOOOo:Llyiahf/vczjk/z98;

    iget-object v5, p0, Llyiahf/vczjk/ae;->OooOOo0:Llyiahf/vczjk/qj8;

    iget-wide v6, p0, Llyiahf/vczjk/ae;->OooOOo:J

    iget v8, p0, Llyiahf/vczjk/ae;->OooOOoo:F

    iget v9, p0, Llyiahf/vczjk/ae;->OooOo00:F

    invoke-static/range {v1 .. v12}, Llyiahf/vczjk/sh5;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ss5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/z98;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
