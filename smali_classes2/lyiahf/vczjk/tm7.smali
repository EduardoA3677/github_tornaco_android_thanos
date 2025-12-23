.class public final Llyiahf/vczjk/tm7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/lang/Class;

.field public final OooO0O0:Llyiahf/vczjk/fq3;


# direct methods
.method public constructor <init>(Ljava/lang/Class;Llyiahf/vczjk/fq3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    iput-object p2, p0, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const/16 v1, 0x2e

    const/16 v2, 0x2f

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object v0

    const-string v1, ".class"

    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/tm7;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/tm7;

    iget-object p1, p1, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-class v1, Llyiahf/vczjk/tm7;

    const-string v2, ": "

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ii5;->OooOOoo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
