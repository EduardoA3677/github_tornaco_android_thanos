.class public final Llyiahf/vczjk/jj3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/kj3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kj3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jj3;->this$0:Llyiahf/vczjk/kj3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/hg2;

    iget-object v0, p0, Llyiahf/vczjk/jj3;->this$0:Llyiahf/vczjk/kj3;

    iget-object v1, v0, Llyiahf/vczjk/kj3;->OooOO0o:Llyiahf/vczjk/qe;

    iget-boolean v2, v0, Llyiahf/vczjk/kj3;->OooOOO:Z

    if-eqz v2, :cond_0

    iget-boolean v2, v0, Llyiahf/vczjk/kj3;->OooOo0o:Z

    if-eqz v2, :cond_0

    if-eqz v1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v3

    invoke-virtual {v2}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v5, v2, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/vz5;

    iget-object v5, v5, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/uqa;

    invoke-virtual {v5}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v5

    invoke-interface {v5, v1}, Llyiahf/vczjk/eq0;->OooOOO0(Llyiahf/vczjk/bq6;)V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/kj3;->OooO0OO(Llyiahf/vczjk/hg2;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw p1

    :cond_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/kj3;->OooO0OO(Llyiahf/vczjk/hg2;)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
