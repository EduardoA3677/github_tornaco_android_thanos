.class public final Llyiahf/vczjk/v65;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $owner:Llyiahf/vczjk/tg6;

.field final synthetic $position:J

.field final synthetic this$0:Llyiahf/vczjk/w65;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w65;Llyiahf/vczjk/tg6;J)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/v65;->this$0:Llyiahf/vczjk/w65;

    iput-object p2, p0, Llyiahf/vczjk/v65;->$owner:Llyiahf/vczjk/tg6;

    iput-wide p3, p0, Llyiahf/vczjk/v65;->$position:J

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/v65;->this$0:Llyiahf/vczjk/w65;

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo0o(Llyiahf/vczjk/ro4;)Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/v65;->this$0:Llyiahf/vczjk/w65;

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-boolean v2, v0, Llyiahf/vczjk/vo4;->OooO0OO:Z

    if-nez v2, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000O0()Llyiahf/vczjk/q65;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/o65;->OooOo0:Llyiahf/vczjk/p65;

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/v65;->this$0:Llyiahf/vczjk/w65;

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    invoke-virtual {v0}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    if-eqz v0, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/o65;->OooOo0:Llyiahf/vczjk/p65;

    :cond_1
    :goto_0
    if-nez v1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/v65;->$owner:Llyiahf/vczjk/tg6;

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getPlacementScope()Llyiahf/vczjk/nw6;

    move-result-object v1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/v65;->this$0:Llyiahf/vczjk/w65;

    iget-wide v2, p0, Llyiahf/vczjk/v65;->$position:J

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    invoke-virtual {v0}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000O0()Llyiahf/vczjk/q65;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v1, v0, v2, v3}, Llyiahf/vczjk/nw6;->OooO0oO(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;J)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
