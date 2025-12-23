.class public final Llyiahf/vczjk/g6a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/i6a;
.implements Llyiahf/vczjk/p29;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/uz;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uz;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g6a;->OooOOO0:Llyiahf/vczjk/uz;

    return-void
.end method


# virtual methods
.method public final OooO0o0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/g6a;->OooOOO0:Llyiahf/vczjk/uz;

    iget-boolean v0, v0, Llyiahf/vczjk/uz;->OooOOo0:Z

    return v0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/g6a;->OooOOO0:Llyiahf/vczjk/uz;

    invoke-virtual {v0}, Llyiahf/vczjk/uz;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method
