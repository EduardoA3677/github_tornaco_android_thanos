.class public final Llyiahf/vczjk/jf5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/kf5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kf5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jf5;->this$0:Llyiahf/vczjk/kf5;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/jf5;->this$0:Llyiahf/vczjk/kf5;

    iget-object v0, v0, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    invoke-virtual {v0}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/o65;->OooOo0:Llyiahf/vczjk/p65;

    if-nez v0, :cond_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/jf5;->this$0:Llyiahf/vczjk/kf5;

    iget-object v0, v0, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-static {v0}, Llyiahf/vczjk/uo4;->OooO00o(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getPlacementScope()Llyiahf/vczjk/nw6;

    move-result-object v0

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/jf5;->this$0:Llyiahf/vczjk/kf5;

    iget-object v2, v1, Llyiahf/vczjk/kf5;->OoooO:Llyiahf/vczjk/oe3;

    iget-object v3, v1, Llyiahf/vczjk/kf5;->OoooOO0:Llyiahf/vczjk/kj3;

    iget-object v4, v1, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    if-eqz v3, :cond_2

    invoke-virtual {v4}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v2

    iget-wide v4, v1, Llyiahf/vczjk/kf5;->o000oOoO:J

    iget v1, v1, Llyiahf/vczjk/kf5;->OoooOOO:F

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v2}, Llyiahf/vczjk/nw6;->OooO00o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;)V

    iget-wide v6, v2, Llyiahf/vczjk/ow6;->OooOOo0:J

    invoke-static {v4, v5, v6, v7}, Llyiahf/vczjk/u14;->OooO0Oo(JJ)J

    move-result-wide v4

    invoke-virtual {v2, v4, v5, v1, v3}, Llyiahf/vczjk/v16;->ooOO(JFLlyiahf/vczjk/kj3;)V

    goto :goto_0

    :cond_2
    if-nez v2, :cond_3

    invoke-virtual {v4}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v2

    iget-wide v3, v1, Llyiahf/vczjk/kf5;->o000oOoO:J

    iget v1, v1, Llyiahf/vczjk/kf5;->OoooOOO:F

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v2}, Llyiahf/vczjk/nw6;->OooO00o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;)V

    iget-wide v5, v2, Llyiahf/vczjk/ow6;->OooOOo0:J

    invoke-static {v3, v4, v5, v6}, Llyiahf/vczjk/u14;->OooO0Oo(JJ)J

    move-result-wide v3

    const/4 v0, 0x0

    invoke-virtual {v2, v3, v4, v1, v0}, Llyiahf/vczjk/ow6;->o0OoOo0(JFLlyiahf/vczjk/oe3;)V

    goto :goto_0

    :cond_3
    invoke-virtual {v4}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v3

    iget-wide v4, v1, Llyiahf/vczjk/kf5;->o000oOoO:J

    iget v1, v1, Llyiahf/vczjk/kf5;->OoooOOO:F

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v3}, Llyiahf/vczjk/nw6;->OooO00o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;)V

    iget-wide v6, v3, Llyiahf/vczjk/ow6;->OooOOo0:J

    invoke-static {v4, v5, v6, v7}, Llyiahf/vczjk/u14;->OooO0Oo(JJ)J

    move-result-wide v4

    invoke-virtual {v3, v4, v5, v1, v2}, Llyiahf/vczjk/ow6;->o0OoOo0(JFLlyiahf/vczjk/oe3;)V

    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
