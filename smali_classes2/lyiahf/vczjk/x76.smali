.class public final Llyiahf/vczjk/x76;
.super Llyiahf/vczjk/r90;
.source "SourceFile"


# instance fields
.field public final OooOOO:[Ljava/lang/Object;

.field public final OooOOO0:Llyiahf/vczjk/j86;

.field public OooOOOO:I

.field public OooOOOo:Z

.field public volatile OooOOo0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j86;[Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/x76;->OooOOO0:Llyiahf/vczjk/j86;

    iput-object p2, p0, Llyiahf/vczjk/x76;->OooOOO:[Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/x76;->OooOOo0:Z

    return-void
.end method

.method public final OooOO0()I
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/x76;->OooOOOo:Z

    return v0
.end method

.method public final OooOOo0()Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/x76;->OooOOOO:I

    iget-object v1, p0, Llyiahf/vczjk/x76;->OooOOO:[Ljava/lang/Object;

    array-length v2, v1

    if-eq v0, v2, :cond_0

    add-int/lit8 v2, v0, 0x1

    iput v2, p0, Llyiahf/vczjk/x76;->OooOOOO:I

    aget-object v0, v1, v0

    const-string v1, "The array element is null"

    invoke-static {v0, v1}, Llyiahf/vczjk/nqa;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final clear()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x76;->OooOOO:[Ljava/lang/Object;

    array-length v0, v0

    iput v0, p0, Llyiahf/vczjk/x76;->OooOOOO:I

    return-void
.end method

.method public final isEmpty()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/x76;->OooOOOO:I

    iget-object v1, p0, Llyiahf/vczjk/x76;->OooOOO:[Ljava/lang/Object;

    array-length v1, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
