.class public final Llyiahf/vczjk/m48;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cg7;


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/m48;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/dg7;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/m48;

    invoke-direct {v0}, Llyiahf/vczjk/m48;-><init>()V

    sput-object v0, Llyiahf/vczjk/m48;->OooO0O0:Llyiahf/vczjk/m48;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/eg7;->OooO00o:Llyiahf/vczjk/dg7;

    iput-object v0, p0, Llyiahf/vczjk/m48;->OooO00o:Llyiahf/vczjk/dg7;

    return-void
.end method


# virtual methods
.method public final OooO00o()[F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m48;->OooO00o:Llyiahf/vczjk/dg7;

    iget-object v0, v0, Llyiahf/vczjk/dg7;->OooO0oO:[F

    return-object v0
.end method

.method public final OooO0O0()[F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m48;->OooO00o:Llyiahf/vczjk/dg7;

    iget-object v0, v0, Llyiahf/vczjk/dg7;->OooO0oo:[F

    return-object v0
.end method

.method public final OooO0OO(FFFF)Llyiahf/vczjk/zf7;
    .locals 6

    iget-object v5, p0, Llyiahf/vczjk/m48;->OooO00o:Llyiahf/vczjk/dg7;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/zf7;

    move v1, p1

    move v2, p2

    move v3, p3

    move v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/zf7;-><init>(FFFFLlyiahf/vczjk/dg7;)V

    return-object v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/ima;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m48;->OooO00o:Llyiahf/vczjk/dg7;

    iget-object v0, v0, Llyiahf/vczjk/dg7;->OooO0O0:Llyiahf/vczjk/ima;

    return-object v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/bg7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m48;->OooO00o:Llyiahf/vczjk/dg7;

    iget-object v0, v0, Llyiahf/vczjk/dg7;->OooO0OO:Llyiahf/vczjk/bg7;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    sget-object v0, Llyiahf/vczjk/eg7;->OooO00o:Llyiahf/vczjk/dg7;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m48;->OooO00o:Llyiahf/vczjk/dg7;

    iget-object v0, v0, Llyiahf/vczjk/dg7;->OooO00o:Ljava/lang/String;

    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    sget-object v0, Llyiahf/vczjk/eg7;->OooO00o:Llyiahf/vczjk/dg7;

    invoke-virtual {v0}, Llyiahf/vczjk/dg7;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "sRGB"

    return-object v0
.end method
