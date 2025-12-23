.class public final Llyiahf/vczjk/fq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $state:Llyiahf/vczjk/lx4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fq1;->$state:Llyiahf/vczjk/lx4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    iget-object v0, p0, Llyiahf/vczjk/fq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooOOo0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
