.class public final Llyiahf/vczjk/np1;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ne8;


# instance fields
.field public OooOoOO:Z

.field public OooOoo:Llyiahf/vczjk/oe3;

.field public final OooOoo0:Z


# direct methods
.method public constructor <init>(ZZLlyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/np1;->OooOoOO:Z

    iput-boolean p2, p0, Llyiahf/vczjk/np1;->OooOoo0:Z

    iput-object p3, p0, Llyiahf/vczjk/np1;->OooOoo:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooOoo()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/np1;->OooOoo0:Z

    return v0
.end method

.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/np1;->OooOoo:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final o0ooOoO()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/np1;->OooOoOO:Z

    return v0
.end method
