.class public final Llyiahf/vczjk/rh2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $color:J

.field final synthetic $fraction:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $onClose:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $open:Z


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;JI)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/rh2;->$open:Z

    iput-object p2, p0, Llyiahf/vczjk/rh2;->$onClose:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/rh2;->$fraction:Llyiahf/vczjk/le3;

    iput-wide p4, p0, Llyiahf/vczjk/rh2;->$color:J

    iput p6, p0, Llyiahf/vczjk/rh2;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-boolean v0, p0, Llyiahf/vczjk/rh2;->$open:Z

    iget-object v1, p0, Llyiahf/vczjk/rh2;->$onClose:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/rh2;->$fraction:Llyiahf/vczjk/le3;

    iget-wide v3, p0, Llyiahf/vczjk/rh2;->$color:J

    iget p1, p0, Llyiahf/vczjk/rh2;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/xh2;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;JLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
