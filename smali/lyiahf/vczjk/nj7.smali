.class public final Llyiahf/vczjk/nj7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $composition:Llyiahf/vczjk/cp1;

.field final synthetic $modifiedValues:Llyiahf/vczjk/ks5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ks5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cp1;Llyiahf/vczjk/ks5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nj7;->$composition:Llyiahf/vczjk/cp1;

    iput-object p2, p0, Llyiahf/vczjk/nj7;->$modifiedValues:Llyiahf/vczjk/ks5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nj7;->$composition:Llyiahf/vczjk/cp1;

    check-cast v0, Llyiahf/vczjk/sg1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/sg1;->OooOoO0(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/nj7;->$modifiedValues:Llyiahf/vczjk/ks5;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ks5;->OooO0Oo(Ljava/lang/Object;)Z

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
