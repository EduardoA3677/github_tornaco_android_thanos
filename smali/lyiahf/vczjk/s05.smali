.class public final Llyiahf/vczjk/s05;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $measurables:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/ef5;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/t05;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/t05;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/s05;->$measurables:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/s05;->this$0:Llyiahf/vczjk/t05;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/s05;->$measurables:Ljava/util/List;

    iget-object v1, p0, Llyiahf/vczjk/s05;->this$0:Llyiahf/vczjk/t05;

    iget-object v1, v1, Llyiahf/vczjk/t05;->OooO00o:Llyiahf/vczjk/le3;

    invoke-static {v0, v1}, Llyiahf/vczjk/sb;->OooOOo0(Ljava/util/List;Llyiahf/vczjk/le3;)Ljava/util/ArrayList;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xn6;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ow6;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/le3;

    if-eqz v3, :cond_0

    invoke-interface {v3}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/u14;

    iget-wide v5, v3, Llyiahf/vczjk/u14;->OooO00o:J

    goto :goto_1

    :cond_0
    const-wide/16 v5, 0x0

    :goto_1
    invoke-static {p1, v4, v5, v6}, Llyiahf/vczjk/nw6;->OooO0oO(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;J)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
