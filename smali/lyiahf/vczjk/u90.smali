.class public final Llyiahf/vczjk/u90;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $lastTextValue$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $onValueChange:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $textFieldValueState$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u90;->$onValueChange:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/u90;->$textFieldValueState$delegate:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/u90;->$lastTextValue$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/gl9;

    iget-object v0, p0, Llyiahf/vczjk/u90;->$textFieldValueState$delegate:Llyiahf/vczjk/qs5;

    invoke-interface {v0, p1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/u90;->$lastTextValue$delegate:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    iget-object v1, p1, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v1, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/u90;->$lastTextValue$delegate:Llyiahf/vczjk/qs5;

    iget-object p1, p1, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v2, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-interface {v1, v2}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/u90;->$onValueChange:Llyiahf/vczjk/oe3;

    iget-object p1, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
