.class public final Llyiahf/vczjk/d89;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/g89;

.field public OooO0O0:Llyiahf/vczjk/fp4;

.field public final OooO0OO:Llyiahf/vczjk/c89;

.field public final OooO0Oo:Llyiahf/vczjk/a89;

.field public final OooO0o0:Llyiahf/vczjk/b89;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g89;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/d89;->OooO00o:Llyiahf/vczjk/g89;

    new-instance p1, Llyiahf/vczjk/c89;

    invoke-direct {p1, p0}, Llyiahf/vczjk/c89;-><init>(Llyiahf/vczjk/d89;)V

    iput-object p1, p0, Llyiahf/vczjk/d89;->OooO0OO:Llyiahf/vczjk/c89;

    new-instance p1, Llyiahf/vczjk/a89;

    invoke-direct {p1, p0}, Llyiahf/vczjk/a89;-><init>(Llyiahf/vczjk/d89;)V

    iput-object p1, p0, Llyiahf/vczjk/d89;->OooO0Oo:Llyiahf/vczjk/a89;

    new-instance p1, Llyiahf/vczjk/b89;

    invoke-direct {p1, p0}, Llyiahf/vczjk/b89;-><init>(Llyiahf/vczjk/d89;)V

    iput-object p1, p0, Llyiahf/vczjk/d89;->OooO0o0:Llyiahf/vczjk/b89;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/fp4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/d89;->OooO0O0:Llyiahf/vczjk/fp4;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "SubcomposeLayoutState is not attached to SubcomposeLayout"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
