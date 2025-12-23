.class public final Llyiahf/vczjk/eda;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/fda;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fda;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/eda;->this$0:Llyiahf/vczjk/fda;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/hg2;

    iget-object v0, p0, Llyiahf/vczjk/eda;->this$0:Llyiahf/vczjk/fda;

    iget-object v1, v0, Llyiahf/vczjk/fda;->OooO0O0:Llyiahf/vczjk/fk3;

    iget v2, v0, Llyiahf/vczjk/fda;->OooOO0O:F

    iget v0, v0, Llyiahf/vczjk/fda;->OooOO0o:F

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v4

    invoke-virtual {v3}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v6

    invoke-interface {v6}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v6, v3, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/vz5;

    const-wide/16 v7, 0x0

    invoke-virtual {v6, v2, v0, v7, v8}, Llyiahf/vczjk/vz5;->OooOOo0(FFJ)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/fk3;->OooO00o(Llyiahf/vczjk/hg2;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {v3, v4, v5}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_0
    move-exception p1

    invoke-static {v3, v4, v5}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw p1
.end method
