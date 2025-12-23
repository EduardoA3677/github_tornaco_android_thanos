.class public final Llyiahf/vczjk/o78;
.super Llyiahf/vczjk/w16;
.source "SourceFile"


# instance fields
.field public final OooO0Oo:Ljava/lang/String;

.field public final OooO0o:Ljava/lang/String;

.field public final OooO0o0:Llyiahf/vczjk/tj2;

.field public final OooO0oO:Llyiahf/vczjk/c73;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/c73;Ljava/lang/String;Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/tj2;)V
    .locals 0

    invoke-direct {p0, p1, p5, p6}, Llyiahf/vczjk/w16;-><init>(Ljava/lang/String;Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;)V

    iput-object p2, p0, Llyiahf/vczjk/o78;->OooO0Oo:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/o78;->OooO0oO:Llyiahf/vczjk/c73;

    if-eqz p4, :cond_1

    iput-object p4, p0, Llyiahf/vczjk/o78;->OooO0o:Ljava/lang/String;

    if-eqz p7, :cond_0

    iput-object p7, p0, Llyiahf/vczjk/o78;->OooO0o0:Llyiahf/vczjk/tj2;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "Style must be provided."

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "Value must be provided."

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-super {p0}, Llyiahf/vczjk/w16;->OooO00o()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ", tag="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/o78;->OooO0Oo:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ", "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/o78;->OooO0oO:Llyiahf/vczjk/c73;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", value="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/o78;->OooO0o:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0()I
    .locals 1

    const/4 v0, 0x6

    return v0
.end method
