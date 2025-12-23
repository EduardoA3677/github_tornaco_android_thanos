.class public final Llyiahf/vczjk/gw2;
.super Llyiahf/vczjk/ec3;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/o000OO;

.field public OooOOOO:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rq8;Llyiahf/vczjk/o000OO;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/ec3;-><init>(Llyiahf/vczjk/rq8;)V

    iput-object p2, p0, Llyiahf/vczjk/gw2;->OooOOO:Llyiahf/vczjk/o000OO;

    return-void
.end method


# virtual methods
.method public final Oooo0O0(Llyiahf/vczjk/yi0;J)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/gw2;->OooOOOO:Z

    if-eqz v0, :cond_0

    invoke-virtual {p1, p2, p3}, Llyiahf/vczjk/yi0;->skip(J)V

    return-void

    :cond_0
    :try_start_0
    invoke-super {p0, p1, p2, p3}, Llyiahf/vczjk/ec3;->Oooo0O0(Llyiahf/vczjk/yi0;J)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p1

    const/4 p2, 0x1

    iput-boolean p2, p0, Llyiahf/vczjk/gw2;->OooOOOO:Z

    iget-object p2, p0, Llyiahf/vczjk/gw2;->OooOOO:Llyiahf/vczjk/o000OO;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/o000OO;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final close()V
    .locals 2

    :try_start_0
    invoke-super {p0}, Llyiahf/vczjk/ec3;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    const/4 v1, 0x1

    iput-boolean v1, p0, Llyiahf/vczjk/gw2;->OooOOOO:Z

    iget-object v1, p0, Llyiahf/vczjk/gw2;->OooOOO:Llyiahf/vczjk/o000OO;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/o000OO;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final flush()V
    .locals 2

    :try_start_0
    invoke-super {p0}, Llyiahf/vczjk/ec3;->flush()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    const/4 v1, 0x1

    iput-boolean v1, p0, Llyiahf/vczjk/gw2;->OooOOOO:Z

    iget-object v1, p0, Llyiahf/vczjk/gw2;->OooOOO:Llyiahf/vczjk/o000OO;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/o000OO;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method
