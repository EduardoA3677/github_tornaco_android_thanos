.class public final Llyiahf/vczjk/kl6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $childConstraints:J

.field final synthetic $horizontalAlignment:Llyiahf/vczjk/m4;

.field final synthetic $orientation:Llyiahf/vczjk/nf6;

.field final synthetic $pageAvailableSize:I

.field final synthetic $pagerItemProvider:Llyiahf/vczjk/gl6;

.field final synthetic $reverseLayout:Z

.field final synthetic $this_measurePager:Llyiahf/vczjk/st4;

.field final synthetic $verticalAlignment:Llyiahf/vczjk/n4;

.field final synthetic $visualPageOffset:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/st4;JLlyiahf/vczjk/gl6;JLlyiahf/vczjk/nf6;Llyiahf/vczjk/m4;Llyiahf/vczjk/n4;ZI)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kl6;->$this_measurePager:Llyiahf/vczjk/st4;

    iput-wide p2, p0, Llyiahf/vczjk/kl6;->$childConstraints:J

    iput-object p4, p0, Llyiahf/vczjk/kl6;->$pagerItemProvider:Llyiahf/vczjk/gl6;

    iput-wide p5, p0, Llyiahf/vczjk/kl6;->$visualPageOffset:J

    iput-object p7, p0, Llyiahf/vczjk/kl6;->$orientation:Llyiahf/vczjk/nf6;

    iput-object p8, p0, Llyiahf/vczjk/kl6;->$horizontalAlignment:Llyiahf/vczjk/m4;

    iput-object p9, p0, Llyiahf/vczjk/kl6;->$verticalAlignment:Llyiahf/vczjk/n4;

    iput-boolean p10, p0, Llyiahf/vczjk/kl6;->$reverseLayout:Z

    iput p11, p0, Llyiahf/vczjk/kl6;->$pageAvailableSize:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result v1

    iget-object v0, p0, Llyiahf/vczjk/kl6;->$this_measurePager:Llyiahf/vczjk/st4;

    iget-wide v2, p0, Llyiahf/vczjk/kl6;->$childConstraints:J

    iget-object v4, p0, Llyiahf/vczjk/kl6;->$pagerItemProvider:Llyiahf/vczjk/gl6;

    iget-wide v5, p0, Llyiahf/vczjk/kl6;->$visualPageOffset:J

    iget-object v7, p0, Llyiahf/vczjk/kl6;->$orientation:Llyiahf/vczjk/nf6;

    iget-object v8, p0, Llyiahf/vczjk/kl6;->$horizontalAlignment:Llyiahf/vczjk/m4;

    iget-object v9, p0, Llyiahf/vczjk/kl6;->$verticalAlignment:Llyiahf/vczjk/n4;

    move-object p1, v0

    check-cast p1, Llyiahf/vczjk/tt4;

    iget-object p1, p1, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v10

    iget-boolean v11, p0, Llyiahf/vczjk/kl6;->$reverseLayout:Z

    iget v12, p0, Llyiahf/vczjk/kl6;->$pageAvailableSize:I

    invoke-static/range {v0 .. v12}, Llyiahf/vczjk/ll6;->OooO0o0(Llyiahf/vczjk/st4;IJLlyiahf/vczjk/gl6;JLlyiahf/vczjk/nf6;Llyiahf/vczjk/m4;Llyiahf/vczjk/n4;Llyiahf/vczjk/yn4;ZI)Llyiahf/vczjk/of5;

    move-result-object p1

    return-object p1
.end method
