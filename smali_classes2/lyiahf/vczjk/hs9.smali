.class public final Llyiahf/vczjk/hs9;
.super Llyiahf/vczjk/x88;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final OooOOo0:J


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/zo1;)V
    .locals 1

    invoke-interface {p3}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-direct {p0, p3, v0}, Llyiahf/vczjk/x88;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V

    iput-wide p1, p0, Llyiahf/vczjk/hs9;->OooOOo0:J

    return-void
.end method


# virtual methods
.method public final OoooO0()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-super {p0}, Llyiahf/vczjk/k84;->OoooO0()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "(timeMillis="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-wide v1, p0, Llyiahf/vczjk/hs9;->OooOOo0:J

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final run()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/o000O000;->OooOOOO:Llyiahf/vczjk/or1;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooOO0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/b52;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Timed out waiting for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-wide v1, p0, Llyiahf/vczjk/hs9;->OooOOo0:J

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v1, " ms"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/gs9;

    invoke-direct {v1, v0, p0}, Llyiahf/vczjk/gs9;-><init>(Ljava/lang/String;Llyiahf/vczjk/hs9;)V

    invoke-virtual {p0, v1}, Llyiahf/vczjk/k84;->OooOOo(Ljava/lang/Object;)Z

    return-void
.end method
