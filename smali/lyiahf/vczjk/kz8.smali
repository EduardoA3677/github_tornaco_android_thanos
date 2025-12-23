.class public final Llyiahf/vczjk/kz8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/tv7;

.field public final OooO0O0:Llyiahf/vczjk/tv7;

.field public final OooO0OO:Llyiahf/vczjk/tv7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tv7;Llyiahf/vczjk/tv7;Llyiahf/vczjk/tv7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kz8;->OooO00o:Llyiahf/vczjk/tv7;

    iput-object p2, p0, Llyiahf/vczjk/kz8;->OooO0O0:Llyiahf/vczjk/tv7;

    iput-object p3, p0, Llyiahf/vczjk/kz8;->OooO0OO:Llyiahf/vczjk/tv7;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_0

    :cond_0
    if-eqz p1, :cond_5

    instance-of v0, p1, Llyiahf/vczjk/kz8;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    check-cast p1, Llyiahf/vczjk/kz8;

    iget-object v0, p1, Llyiahf/vczjk/kz8;->OooO00o:Llyiahf/vczjk/tv7;

    iget-object v1, p0, Llyiahf/vczjk/kz8;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/tv7;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/kz8;->OooO0O0:Llyiahf/vczjk/tv7;

    iget-object v1, p1, Llyiahf/vczjk/kz8;->OooO0O0:Llyiahf/vczjk/tv7;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/tv7;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_1

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/kz8;->OooO0OO:Llyiahf/vczjk/tv7;

    iget-object p1, p1, Llyiahf/vczjk/kz8;->OooO0OO:Llyiahf/vczjk/tv7;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_4

    goto :goto_1

    :cond_4
    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_5
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/kz8;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-virtual {v0}, Llyiahf/vczjk/tv7;->hashCode()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/kz8;->OooO0O0:Llyiahf/vczjk/tv7;

    mul-int/lit8 v0, v0, 0x1f

    invoke-virtual {v1}, Llyiahf/vczjk/tv7;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    iget-object v0, p0, Llyiahf/vczjk/kz8;->OooO0OO:Llyiahf/vczjk/tv7;

    if-eqz v0, :cond_0

    mul-int/lit8 v1, v1, 0x1f

    invoke-virtual {v0}, Llyiahf/vczjk/tv7;->hashCode()I

    move-result v0

    add-int/2addr v0, v1

    return v0

    :cond_0
    return v1
.end method
