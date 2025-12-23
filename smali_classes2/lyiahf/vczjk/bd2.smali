.class public final Llyiahf/vczjk/bd2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/ze3;

.field public final OooOOO0:Llyiahf/vczjk/f43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bd2;->OooOOO0:Llyiahf/vczjk/f43;

    iput-object p2, p0, Llyiahf/vczjk/bd2;->OooOOO:Llyiahf/vczjk/ze3;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/hl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sget-object v1, Llyiahf/vczjk/bua;->OooO0Oo:Llyiahf/vczjk/h87;

    iput-object v1, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    new-instance v1, Llyiahf/vczjk/ad2;

    invoke-direct {v1, p0, v0, p1}, Llyiahf/vczjk/ad2;-><init>(Llyiahf/vczjk/bd2;Llyiahf/vczjk/hl7;Llyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/bd2;->OooOOO0:Llyiahf/vczjk/f43;

    invoke-interface {p1, v1, p2}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
