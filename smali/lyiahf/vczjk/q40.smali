.class public final Llyiahf/vczjk/q40;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $enabled:Z

.field final synthetic $onBack:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/le3;II)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/q40;->$enabled:Z

    iput-object p2, p0, Llyiahf/vczjk/q40;->$onBack:Llyiahf/vczjk/le3;

    iput p3, p0, Llyiahf/vczjk/q40;->$$changed:I

    iput p4, p0, Llyiahf/vczjk/q40;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-boolean p2, p0, Llyiahf/vczjk/q40;->$enabled:Z

    iget-object v0, p0, Llyiahf/vczjk/q40;->$onBack:Llyiahf/vczjk/le3;

    iget v1, p0, Llyiahf/vczjk/q40;->$$changed:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    iget v2, p0, Llyiahf/vczjk/q40;->$$default:I

    invoke-static {p2, v0, p1, v1, v2}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
