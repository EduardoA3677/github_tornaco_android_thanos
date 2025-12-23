.class public abstract Llyiahf/vczjk/nt1;
.super Llyiahf/vczjk/g14;
.source "SourceFile"


# instance fields
.field public final OooOOo0:Llyiahf/vczjk/hj1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;Llyiahf/vczjk/hj1;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3, p4}, Llyiahf/vczjk/g14;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;)V

    if-eqz p5, :cond_0

    iput-object p5, p0, Llyiahf/vczjk/nt1;->OooOOo0:Llyiahf/vczjk/hj1;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "cst == null"

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public OooO0o0()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nt1;->OooOOo0:Llyiahf/vczjk/hj1;

    invoke-interface {v0}, Llyiahf/vczjk/ss9;->OooO00o()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
