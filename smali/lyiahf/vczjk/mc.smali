.class public final Llyiahf/vczjk/mc;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $modifier:Llyiahf/vczjk/kl5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mc;->$modifier:Llyiahf/vczjk/kl5;

    iput p2, p0, Llyiahf/vczjk/mc;->$$changed:I

    iput p3, p0, Llyiahf/vczjk/mc;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object p2, p0, Llyiahf/vczjk/mc;->$modifier:Llyiahf/vczjk/kl5;

    iget v0, p0, Llyiahf/vczjk/mc;->$$changed:I

    or-int/lit8 v0, v0, 0x1

    invoke-static {v0}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/mc;->$$default:I

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/qc;->OooO0O0(IILlyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
