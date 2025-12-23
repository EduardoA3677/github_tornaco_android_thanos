.class public final Llyiahf/vczjk/u12;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/px3;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/u12;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/u12;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/u12;->OooO00o:Llyiahf/vczjk/u12;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n24;)Llyiahf/vczjk/l52;
    .locals 1

    new-instance v0, Llyiahf/vczjk/t12;

    invoke-direct {v0, p1}, Llyiahf/vczjk/t12;-><init>(Llyiahf/vczjk/n24;)V

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    if-ne p1, p0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    const/4 v0, -0x1

    return v0
.end method
