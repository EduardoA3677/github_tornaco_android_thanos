.class public final Llyiahf/vczjk/uj4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:I

.field public final OooO0O0:Llyiahf/vczjk/or5;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 v0, 0x12c

    iput v0, p0, Llyiahf/vczjk/uj4;->OooO00o:I

    sget-object v0, Llyiahf/vczjk/t14;->OooO00o:Llyiahf/vczjk/or5;

    new-instance v0, Llyiahf/vczjk/or5;

    invoke-direct {v0}, Llyiahf/vczjk/or5;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/uj4;->OooO0O0:Llyiahf/vczjk/or5;

    return-void
.end method


# virtual methods
.method public final OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;
    .locals 2

    new-instance v0, Llyiahf/vczjk/tj4;

    sget-object v1, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    invoke-direct {v0, p2, v1}, Llyiahf/vczjk/tj4;-><init>(Ljava/lang/Object;Llyiahf/vczjk/ik2;)V

    iget-object p2, p0, Llyiahf/vczjk/uj4;->OooO0O0:Llyiahf/vczjk/or5;

    invoke-virtual {p2, p1, v0}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    return-object v0
.end method
