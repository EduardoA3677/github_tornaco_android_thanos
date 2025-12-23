.class public final Llyiahf/vczjk/do0;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/hc3;

.field public final OooO0O0:Llyiahf/vczjk/qt5;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/vy8;->OooO0o:Llyiahf/vczjk/qt5;

    sget-object v1, Llyiahf/vczjk/hc3;->OooO0OO:Llyiahf/vczjk/hc3;

    invoke-static {v0}, Llyiahf/vczjk/r02;->Oooo00O(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V
    .locals 1

    const-string v0, "packageName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/do0;->OooO00o:Llyiahf/vczjk/hc3;

    iput-object p2, p0, Llyiahf/vczjk/do0;->OooO0O0:Llyiahf/vczjk/qt5;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/do0;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    check-cast p1, Llyiahf/vczjk/do0;

    iget-object v0, p1, Llyiahf/vczjk/do0;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v1, p0, Llyiahf/vczjk/do0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/do0;->OooO0O0:Llyiahf/vczjk/qt5;

    iget-object p1, p1, Llyiahf/vczjk/do0;->OooO0O0:Llyiahf/vczjk/qt5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_2
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/do0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->hashCode()I

    move-result v0

    add-int/lit16 v0, v0, 0x20f

    mul-int/lit16 v0, v0, 0x3c1

    iget-object v1, p0, Llyiahf/vczjk/do0;->OooO0O0:Llyiahf/vczjk/qt5;

    invoke-virtual {v1}, Llyiahf/vczjk/qt5;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/do0;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v1, v1, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    const/16 v2, 0x2e

    const/16 v3, 0x2f

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "/"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/do0;->OooO0O0:Llyiahf/vczjk/qt5;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
