.class public final Llyiahf/vczjk/oj;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $currentSize:J

.field final synthetic this$0:Llyiahf/vczjk/pj;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/pj;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pj;J)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oj;->this$0:Llyiahf/vczjk/pj;

    iput-wide p2, p0, Llyiahf/vczjk/oj;->$currentSize:J

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/oj;->this$0:Llyiahf/vczjk/pj;

    iget-object v0, v0, Llyiahf/vczjk/pj;->OooOoo:Llyiahf/vczjk/uj;

    invoke-virtual {v0}, Llyiahf/vczjk/uj;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/oj;->this$0:Llyiahf/vczjk/pj;

    iget-wide v0, p0, Llyiahf/vczjk/oj;->$currentSize:J

    iget-wide v2, p1, Llyiahf/vczjk/pj;->OooOooO:J

    sget-wide v4, Landroidx/compose/animation/OooO00o;->OooO00o:J

    invoke-static {v2, v3, v4, v5}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_0
    iget-wide v0, p1, Llyiahf/vczjk/pj;->OooOooO:J

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/oj;->this$0:Llyiahf/vczjk/pj;

    iget-object v0, v0, Llyiahf/vczjk/pj;->OooOoo:Llyiahf/vczjk/uj;

    iget-object v0, v0, Llyiahf/vczjk/uj;->OooO0o0:Llyiahf/vczjk/js5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p29;

    if-eqz p1, :cond_2

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v0, p1, Llyiahf/vczjk/b24;->OooO00o:J

    goto :goto_0

    :cond_2
    const-wide/16 v0, 0x0

    :goto_0
    new-instance p1, Llyiahf/vczjk/b24;

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/b24;-><init>(J)V

    return-object p1
.end method
