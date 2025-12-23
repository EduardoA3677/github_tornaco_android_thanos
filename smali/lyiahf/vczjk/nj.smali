.class public final Llyiahf/vczjk/nj;
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

    iput-object p1, p0, Llyiahf/vczjk/nj;->this$0:Llyiahf/vczjk/pj;

    iput-wide p2, p0, Llyiahf/vczjk/nj;->$currentSize:J

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/sy9;

    invoke-interface {p1}, Llyiahf/vczjk/sy9;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/nj;->this$0:Llyiahf/vczjk/pj;

    iget-object v1, v1, Llyiahf/vczjk/pj;->OooOoo:Llyiahf/vczjk/uj;

    invoke-virtual {v1}, Llyiahf/vczjk/uj;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    const-wide/16 v1, 0x0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/nj;->this$0:Llyiahf/vczjk/pj;

    iget-wide v3, p0, Llyiahf/vczjk/nj;->$currentSize:J

    iget-wide v5, v0, Llyiahf/vczjk/pj;->OooOooO:J

    sget-wide v7, Landroidx/compose/animation/OooO00o;->OooO00o:J

    invoke-static {v5, v6, v7, v8}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v5

    if-eqz v5, :cond_0

    goto :goto_0

    :cond_0
    iget-wide v3, v0, Llyiahf/vczjk/pj;->OooOooO:J

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/nj;->this$0:Llyiahf/vczjk/pj;

    iget-object v0, v0, Llyiahf/vczjk/pj;->OooOoo:Llyiahf/vczjk/uj;

    iget-object v0, v0, Llyiahf/vczjk/uj;->OooO0o0:Llyiahf/vczjk/js5;

    invoke-interface {p1}, Llyiahf/vczjk/sy9;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/p29;

    if-eqz v0, :cond_2

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/b24;

    iget-wide v3, v0, Llyiahf/vczjk/b24;->OooO00o:J

    goto :goto_0

    :cond_2
    move-wide v3, v1

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/nj;->this$0:Llyiahf/vczjk/pj;

    iget-object v0, v0, Llyiahf/vczjk/pj;->OooOoo:Llyiahf/vczjk/uj;

    iget-object v0, v0, Llyiahf/vczjk/uj;->OooO0o0:Llyiahf/vczjk/js5;

    invoke-interface {p1}, Llyiahf/vczjk/sy9;->OooO0OO()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p29;

    if-eqz p1, :cond_3

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v1, p1, Llyiahf/vczjk/b24;->OooO00o:J

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/nj;->this$0:Llyiahf/vczjk/pj;

    iget-object p1, p1, Llyiahf/vczjk/pj;->OooOoo0:Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/br8;

    if-eqz p1, :cond_5

    new-instance v0, Llyiahf/vczjk/b24;

    invoke-direct {v0, v3, v4}, Llyiahf/vczjk/b24;-><init>(J)V

    new-instance v3, Llyiahf/vczjk/b24;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/b24;-><init>(J)V

    iget-object p1, p1, Llyiahf/vczjk/br8;->OooO0O0:Llyiahf/vczjk/ze3;

    invoke-interface {p1, v0, v3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p13;

    if-nez p1, :cond_4

    goto :goto_1

    :cond_4
    return-object p1

    :cond_5
    :goto_1
    const/high16 p1, 0x43c80000    # 400.0f

    const/4 v0, 0x5

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-static {v1, p1, v2, v0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object p1

    return-object p1
.end method
