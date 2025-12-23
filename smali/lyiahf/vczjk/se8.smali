.class public final Llyiahf/vczjk/se8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/je8;

.field public final OooO0O0:Llyiahf/vczjk/pr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/re8;Llyiahf/vczjk/s14;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iput-object v0, p0, Llyiahf/vczjk/se8;->OooO00o:Llyiahf/vczjk/je8;

    new-instance v0, Llyiahf/vczjk/pr5;

    const/4 v1, 0x4

    invoke-static {v1, p1}, Llyiahf/vczjk/re8;->OooO0oo(ILlyiahf/vczjk/re8;)Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    invoke-direct {v0, v2}, Llyiahf/vczjk/pr5;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/se8;->OooO0O0:Llyiahf/vczjk/pr5;

    invoke-static {v1, p1}, Llyiahf/vczjk/re8;->OooO0oo(ILlyiahf/vczjk/re8;)Ljava/util/List;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/re8;

    iget v3, v2, Llyiahf/vczjk/re8;->OooO0oO:I

    invoke-virtual {p2, v3}, Llyiahf/vczjk/s14;->OooO00o(I)Z

    move-result v3

    if-eqz v3, :cond_0

    iget-object v3, p0, Llyiahf/vczjk/se8;->OooO0O0:Llyiahf/vczjk/pr5;

    iget v2, v2, Llyiahf/vczjk/re8;->OooO0oO:I

    invoke-virtual {v3, v2}, Llyiahf/vczjk/pr5;->OooO00o(I)Z

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method
