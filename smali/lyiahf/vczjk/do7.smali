.class public final Llyiahf/vczjk/do7;
.super Llyiahf/vczjk/fu6;
.source "SourceFile"


# instance fields
.field public final OooO0Oo:Llyiahf/vczjk/fu6;

.field public final OooO0o0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fu6;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/do7;->OooO0Oo:Llyiahf/vczjk/fu6;

    iput p2, p0, Llyiahf/vczjk/do7;->OooO0o0:I

    return-void
.end method


# virtual methods
.method public final OooOOO0(Llyiahf/vczjk/js8;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/xx8;

    iget-object v1, p0, Llyiahf/vczjk/do7;->OooO0Oo:Llyiahf/vczjk/fu6;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/fu6;->OooOOO0(Llyiahf/vczjk/js8;)Ljava/lang/Object;

    move-result-object p1

    iget v1, p0, Llyiahf/vczjk/do7;->OooO0o0:I

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/xx8;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method
