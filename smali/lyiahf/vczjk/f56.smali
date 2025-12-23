.class public final Llyiahf/vczjk/f56;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u46;
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/f56;

.field public static final OooOOO0:Llyiahf/vczjk/f56;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _access:Llyiahf/vczjk/o0OoO00O;

.field protected final _nullValue:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/f56;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/f56;-><init>(Ljava/lang/Object;)V

    sput-object v0, Llyiahf/vczjk/f56;->OooOOO0:Llyiahf/vczjk/f56;

    new-instance v0, Llyiahf/vczjk/f56;

    invoke-direct {v0, v1}, Llyiahf/vczjk/f56;-><init>(Ljava/lang/Object;)V

    sput-object v0, Llyiahf/vczjk/f56;->OooOOO:Llyiahf/vczjk/f56;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/f56;->_nullValue:Ljava/lang/Object;

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/o0OoO00O;->OooOOO0:Llyiahf/vczjk/o0OoO00O;

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/o0OoO00O;->OooOOO:Llyiahf/vczjk/o0OoO00O;

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/f56;->_access:Llyiahf/vczjk/o0OoO00O;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/u46;)Z
    .locals 1

    sget-object v0, Llyiahf/vczjk/f56;->OooOOO0:Llyiahf/vczjk/f56;

    if-ne p0, v0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/f56;->_nullValue:Ljava/lang/Object;

    return-object p1
.end method
